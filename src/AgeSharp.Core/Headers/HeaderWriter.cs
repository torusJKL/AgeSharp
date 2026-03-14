using System.Security.Cryptography;
using System.Text;

using AgeSharp.Core.Encoding;

namespace AgeSharp.Core.Headers;

internal static class HeaderWriter
{
    private const string VersionLine = "age-encryption.org/v1";
    private const int MacBase64Length = 43;
    private const string LineEnding = "\n";

    internal static string Write(IReadOnlyList<Stanza> stanzas, byte[] fileKey)
    {
        ArgumentNullException.ThrowIfNull(stanzas);
        ArgumentNullException.ThrowIfNull(fileKey);

        if (stanzas.Count == 0)
        {
            throw new ArgumentException("At least one stanza is required");
        }

        var sb = new StringBuilder();

        sb.Append(VersionLine);
        sb.Append(LineEnding);

        foreach (var stanza in stanzas)
        {
            foreach (var line in stanza.GetStanzaLines())
            {
                sb.Append(line);
                sb.Append(LineEnding);
            }
        }

        var macKey = DeriveMacKey(fileKey);
        var mac = ComputeMac(sb, macKey);

        sb.Append("--- ");
        sb.Append(mac);
        sb.Append(LineEnding);

        return sb.ToString();
    }

    private static byte[] DeriveMacKey(byte[] fileKey)
    {
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, fileKey, 32, Array.Empty<byte>(), "header"u8.ToArray());
    }

    private static string ComputeMac(StringBuilder sb, byte[] macKey)
    {
        var headerBytes = System.Text.Encoding.ASCII.GetBytes(sb.ToString() + "---");
        using var hmac = new HMACSHA256(macKey);
        var hash = hmac.ComputeHash(headerBytes);
        return Base64NoPadding.Encode(hash);
    }
}
