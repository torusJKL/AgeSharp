using System.Linq;
using System.Security.Cryptography;
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

    internal static (List<ParsedStanza> Stanzas, string Mac) Read(byte[] headerBytes)
    {
        if (headerBytes.Any(b => b > 0x7F))
        {
            throw new AgeFormatException("Header contains non-ASCII bytes");
        }

        return Read(System.Text.Encoding.ASCII.GetString(headerBytes));
    }

    internal static (List<ParsedStanza> Stanzas, string Mac) Read(string header)
    {
        ArgumentNullException.ThrowIfNull(header);
        ValidateLineEndings(header);

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

        if (stanzas.Count > 1 && stanzas.Any(s => s.Type == "scrypt"))
        {
            throw new AgeFormatException("Scrypt stanza cannot be mixed with other recipient types");
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

        if (mac.Any(c => !IsValidBase64NoPaddingChar(c)))
        {
            throw new AgeFormatException("Invalid MAC character");
        }

        if (mac.Contains('='))
        {
            throw new AgeFormatException("MAC contains padding");
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
        var computedMacBytes = ComputeMac(headerText, macKey);

        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(providedMac),
            System.Text.Encoding.ASCII.GetBytes(computedMacBytes));
    }

    private static bool IsValidBase64NoPaddingChar(char c)
    {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '+' ||
               c == '/';
    }

    private static bool IsValidVChar(char c)
    {
        return c >= 0x21 && c <= 0x7E;
    }

    private static void ValidateNoPadding(string encoded)
    {
        if (encoded.Contains('='))
        {
            throw new AgeFormatException("Base64 contains padding characters.");
        }
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

        foreach (var arg in args)
        {
            if (string.IsNullOrEmpty(arg))
            {
                throw new AgeFormatException("Invalid stanza argument: empty component");
            }

            if (arg.Any(c => !IsValidVChar(c)))
            {
                throw new AgeFormatException("Invalid stanza argument character");
            }
        }

        var type = args[0];
        var arguments = args.Length > 1 ? args[1..] : Array.Empty<string>();

        if (type == "X25519" && arguments.Length == 1)
        {
            var argBytes = Base64NoPadding.Decode(arguments[0]);
            if (argBytes.Length != 32)
            {
                throw new AgeFormatException("X25519 argument must be 32 bytes");
            }
            var canonical = Base64NoPadding.Encode(argBytes);
            if (canonical != arguments[0])
            {
                throw new AgeFormatException("X25519 argument uses non-canonical base64 encoding");
            }
        }

        if (type == "X25519" && arguments.Length != 1)
        {
            throw new AgeFormatException($"X25519 stanza must have exactly 1 argument, got {arguments.Length}");
        }

        if (type == "scrypt")
        {
            if (arguments.Length != 2)
            {
                throw new AgeFormatException($"Scrypt stanza must have exactly 2 arguments, got {arguments.Length}");
            }

            try
            {
                var salt = Base64NoPadding.Decode(arguments[0]);
                if (salt.Length != 16)
                {
                    throw new AgeFormatException("Scrypt salt must be 16 bytes");
                }
                var canonicalSalt = Base64NoPadding.Encode(salt);
                if (canonicalSalt != arguments[0])
                {
                    throw new AgeFormatException("Scrypt salt uses non-canonical base64 encoding");
                }
            }
            catch (FormatException)
            {
                throw new AgeFormatException("Invalid scrypt salt: not valid base64");
            }

            var logNStr = arguments[1];
            if (!System.Text.RegularExpressions.Regex.IsMatch(logNStr, @"^[1-9][0-9]*$"))
            {
                throw new AgeFormatException("Scrypt logN must be a decimal number with no leading zeros");
            }

            if (!int.TryParse(logNStr, out var logN) || logN < 1)
            {
                throw new AgeFormatException("Invalid scrypt logN");
            }

            if (logN > 22)
            {
                throw new AgeFormatException("Scrypt logN exceeds maximum allowed value of 22");
            }
        }

        ++index;

        var bodyText = new StringBuilder();
        var bodyLineCount = 0;
        var foundFinalLine = false;
        while (index < lines.Length)
        {
            var line = lines[index];

            if (line.StartsWith("-> ") || line.StartsWith("--- "))
            {
                break;
            }

            if (string.IsNullOrEmpty(line))
            {
                foundFinalLine = true;
                ++index;
                break;
            }

            if (line.Length > 64)
            {
                throw new AgeFormatException("Stanza line too long");
            }

            foreach (var c in line)
            {
                if (!IsValidBase64NoPaddingChar(c))
                {
                    throw new AgeFormatException("Invalid stanza body character");
                }
            }

            if (line.Contains('='))
            {
                throw new AgeFormatException("Stanza body contains padding");
            }

            bodyText.Append(line);
            ++index;
            bodyLineCount++;

            if (line.Length < 64)
            {
                foundFinalLine = true;
                break;
            }
        }

        if (!foundFinalLine)
        {
            throw new AgeFormatException("Stanza body must end with a short line (less than 64 characters)");
        }

        byte[] body;
        if (bodyText.Length > 0)
        {
            body = Base64NoPadding.Decode(bodyText.ToString());
            var canonical = Base64NoPadding.Encode(body);
            if (canonical != bodyText.ToString())
            {
                throw new AgeFormatException("Stanza body uses non-canonical base64 encoding");
            }
        }
        else
        {
            body = Array.Empty<byte>();
        }

        if (type == "scrypt" && body.Length != 32)
        {
            throw new AgeFormatException("Scrypt body must be exactly 32 bytes");
        }

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

    internal static void ValidateLineEndings(string header)
    {
        if (header.Contains("\r\n"))
        {
            throw new AgeFormatException("Header uses CRLF line endings instead of LF");
        }
    }
}
