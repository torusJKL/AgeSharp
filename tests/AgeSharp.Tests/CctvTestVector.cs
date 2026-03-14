using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace AgeSharp.Tests;

public class CctvTestVector
{
    public string Name { get; init; } = string.Empty;
    public string Expect { get; init; } = string.Empty;
    public string? PayloadHash { get; init; }
    public string? FileKey { get; init; }
    public List<string> Identities { get; init; } = new();
    public List<string> Passphrases { get; init; } = new();
    public bool IsArmored { get; init; }
    public bool IsCompressed { get; init; }
    public string? Comment { get; init; }
    public byte[] EncryptedData { get; init; } = Array.Empty<byte>();

    private static readonly Regex HeaderRegex = new(@"^(\w+):\s*(.*)$", RegexOptions.Multiline);

    public static CctvTestVector Parse(string name, byte[] content)
    {
        var headerEndIndex = -1;
        for (var i = 0; i < content.Length - 1; i++)
        {
            if (content[i] == '\n' && content[i + 1] == '\n')
            {
                headerEndIndex = i;
                break;
            }
            if (i < content.Length - 2 && content[i] == '\n' && content[i + 1] == '\r' && content[i + 2] == '\n')
            {
                headerEndIndex = i;
                break;
            }
        }

        if (headerEndIndex < 0)
        {
            throw new ArgumentException("Invalid test vector format: no empty line found");
        }

        var headerBytes = content[..headerEndIndex];
        var headerText = System.Text.Encoding.ASCII.GetString(headerBytes);
        var payloadStartIndex = headerEndIndex + 1;
        if (payloadStartIndex < content.Length - 1 && content[payloadStartIndex] == '\r')
        {
            payloadStartIndex++;
        }
        payloadStartIndex++;
        var encryptedData = content[payloadStartIndex..];

        return ParseFromParts(name, headerText, encryptedData);
    }

    public static CctvTestVector Parse(string name, string content)
    {
        return Parse(name, System.Text.Encoding.UTF8.GetBytes(content));
    }

    private static CctvTestVector ParseFromParts(string name, string headerText, byte[] encryptedData)
    {
        var lines = headerText.Split('\n');
        var header = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var match = HeaderRegex.Match(line);
            if (match.Success)
            {
                var key = match.Groups[1].Value;
                var value = match.Groups[2].Value;

                if (!header.TryGetValue(key, out var list))
                {
                    list = new List<string>();
                    header[key] = list;
                }
                list.Add(value);
            }
        }

        return new CctvTestVector
        {
            Name = name,
            Expect = header.GetValueOrDefault("expect")?.FirstOrDefault() ?? "success",
            PayloadHash = header.GetValueOrDefault("payload")?.FirstOrDefault(),
            FileKey = header.GetValueOrDefault("file key")?.FirstOrDefault(),
            Identities = header.GetValueOrDefault("identity") ?? new List<string>(),
            Passphrases = header.GetValueOrDefault("passphrase") ?? new List<string>(),
            IsArmored = header.GetValueOrDefault("armored")?.FirstOrDefault() == "yes",
            IsCompressed = header.GetValueOrDefault("compressed")?.FirstOrDefault() == "zlib",
            Comment = header.GetValueOrDefault("comment")?.FirstOrDefault(),
            EncryptedData = encryptedData
        };
    }

    public static byte[] HexToBytes(string hex)
    {
        hex = hex.Replace(" ", "").Replace("\n", "");
        var bytes = new byte[hex.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    public bool VerifyPayloadHash(byte[] payload)
    {
        if (string.IsNullOrEmpty(PayloadHash))
        {
            return true;
        }

        var hash = SHA256.HashData(payload);
        var hashHex = Convert.ToHexString(hash).ToLowerInvariant();
        return hashHex == PayloadHash.ToLowerInvariant();
    }
}
