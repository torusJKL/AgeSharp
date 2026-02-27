using System.Text;

using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;

namespace AgeSharp.Core.Headers;

internal sealed class ParsedStanza
{
    private static readonly Dictionary<string, Func<ParsedStanza, string?>> RecipientKeyConverters = new()
    {
        ["X25519"] = X25519ToRecipientKey
    };

    public string Type { get; }
    public string[] Arguments { get; }
    public byte[] Body { get; }

    public ParsedStanza(string type, string[] arguments, byte[] body)
    {
        Type = type;
        Arguments = arguments;
        Body = body;
    }

    public string? TryGetRecipientKey()
    {
        return RecipientKeyConverters.TryGetValue(Type, out var converter) 
            ? converter(this) 
            : null;
    }

    private static string? X25519ToRecipientKey(ParsedStanza stanza)
    {
        if (stanza.Arguments.Length == 0)
        {
            return null;
        }

        try
        {
            var ephemeralKey = Base64NoPadding.Decode(stanza.Arguments[0]);
            if (ephemeralKey.Length != 32)
            {
                return null;
            }

            return AgeBech32.EncodeRecipient(ephemeralKey);
        }
        catch
        {
            return null;
        }
    }
}

internal static class HeaderReader
{
    private const string VersionLine = "age-encryption.org/v1";
    private const int MacBase64Length = 43;

    internal static (List<ParsedStanza> Stanzas, string Mac) Read(string header)
    {
        ArgumentNullException.ThrowIfNull(header);

        var lines = header.Split('\n');

        if (lines.Length == 0 || lines[0] != VersionLine)
        {
            throw new AgeFormatException("Invalid version line");
        }

        var stanzas = new List<ParsedStanza>();

        var i = 1;
        while (i < lines.Length)
        {
            var line = lines[i];

            if (string.IsNullOrWhiteSpace(line))
            {
                i++;
                continue;
            }

            if (line.StartsWith("--- "))
            {
                if (stanzas.Count == 0)
                {
                    throw new AgeFormatException("MAC must come after stanzas");
                }
                break;
            }

            var stanza = ParseStanza(lines, ref i);
            stanzas.Add(stanza);
        }

        if (i >= lines.Length)
        {
            throw new AgeFormatException("Missing MAC");
        }

        var mac = lines[i][4..];
        if (mac.Length != MacBase64Length)
        {
            throw new AgeFormatException($"Invalid MAC length: expected {MacBase64Length}, got {mac.Length}");
        }

        return (stanzas, mac);
    }

    internal static bool VerifyMac(string header, byte[] fileKey)
    {
        var lines = header.Split('\n');

        var macLineIndex = -1;
        for (var i = lines.Length - 1; i >= 1; i--)
        {
            if (!string.IsNullOrWhiteSpace(lines[i]) && lines[i].StartsWith("--- "))
            {
                macLineIndex = i;
                break;
            }
        }

        if (macLineIndex < 0)
        {
            return false;
        }

        var providedMac = lines[macLineIndex][4..];

        var headerForMac = new List<string>();
        for (var i = 0; i < macLineIndex; i++)
        {
            headerForMac.Add(lines[i]);
        }

        var headerText = string.Join("\n", headerForMac);
        var macKey = DeriveMacKey(fileKey);
        var computedMac = ComputeMac(headerText, macKey);

        return providedMac == computedMac;
    }

    private static ParsedStanza ParseStanza(string[] lines, ref int index)
    {
        var argLine = lines[index];
        if (!argLine.StartsWith("-> "))
        {
            throw new AgeFormatException("Invalid stanza");
        }

        var args = argLine[3..].Split(' ');
        if (args.Length == 0)
        {
            throw new AgeFormatException("Invalid stanza arguments");
        }

        var type = args[0];
        var arguments = args.Length > 1 ? args[1..] : Array.Empty<string>();

        ++index;

        var bodyText = new StringBuilder();
        while (index < lines.Length)
        {
            var line = lines[index];

            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("-> ") || line.StartsWith("--- "))
            {
                break;
            }

            if (line.Length > 64)
            {
                throw new AgeFormatException("Stanza line too long");
            }

            bodyText.Append(line);
            ++index;

            if (line.Length < 64)
            {
                break;
            }
        }
        var body = Base64NoPadding.Decode(bodyText.ToString());

        return new ParsedStanza(type, arguments, body);
    }

    private static byte[] DeriveMacKey(byte[] fileKey)
    {
        return System.Security.Cryptography.HKDF.DeriveKey(
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            fileKey, 32,
            Array.Empty<byte>(),
            "header"u8.ToArray());
    }

    private static string ComputeMac(string headerText, byte[] macKey)
    {
        var headerBytes = System.Text.Encoding.ASCII.GetBytes(headerText + "\n---");
        using var hmac = new System.Security.Cryptography.HMACSHA256(macKey);
        var hash = hmac.ComputeHash(headerBytes);
        return Base64NoPadding.Encode(hash);
    }
}
