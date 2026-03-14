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

    public static CctvTestVector Parse(string name, string content)
    {
        var lines = content.Split('\n');
        var headerEndIndex = -1;
        var header = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line))
            {
                headerEndIndex = i;
                break;
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

        if (headerEndIndex < 0)
        {
            throw new ArgumentException("Invalid test vector format: no empty line found");
        }

        var encryptedLines = lines.Skip(headerEndIndex + 1);
        var encryptedContent = string.Join("\n", encryptedLines);

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
            EncryptedData = System.Text.Encoding.UTF8.GetBytes(encryptedContent)
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
