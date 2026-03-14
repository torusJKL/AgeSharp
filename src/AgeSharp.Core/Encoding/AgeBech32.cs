using System.Collections.Frozen;
using System.Text;

using AgeSharp.Core.Exceptions;

namespace AgeSharp.Core.Encoding;

internal static class AgeBech32
{
    internal const string IdentityHrp = "AGE-SECRET-KEY-";
    internal const string RecipientHrp = "age";

    private const int ChecksumLength = 6;
    private const int MaxHrpLength = 83;
    private const int MinDataLength = 6;

    private static readonly int[] Bech32Generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    private static readonly FrozenDictionary<char, int> CharsetValues;
    private static readonly char[] CharsetUpper = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L".ToCharArray();
    private static readonly char[] CharsetLower = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".ToCharArray();

    static AgeBech32()
    {
        var dict = new Dictionary<char, int>();
        for (var i = 0; i < CharsetUpper.Length; i++)
        {
            var c = CharsetUpper[i];
            dict[c] = i;
            dict[char.ToLowerInvariant(c)] = i;
        }
        CharsetValues = FrozenDictionary.ToFrozenDictionary(dict);
    }

    internal static string EncodeIdentity(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (data.Length == 0)
        {
            throw new ArgumentException("Data cannot be empty", nameof(data));
        }

        return Encode(data, IdentityHrp);
    }

    internal static string EncodeRecipient(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (data.Length == 0)
        {
            throw new ArgumentException("Data cannot be empty", nameof(data));
        }

        return Encode(data, RecipientHrp);
    }

    private static string Encode(byte[] data, string hrp)
    {
        var words = ConvertBits(data, 8, 5, true);
        return EncodeWords(hrp, words);
    }

    internal static byte[] DecodeIdentity(string encoded)
    {
        ArgumentNullException.ThrowIfNull(encoded);

        return Decode(encoded, IdentityHrp);
    }

    internal static byte[] DecodeIdentityToPrivateKey(string encoded)
    {
        return DecodeIdentity(encoded);
    }

    internal static byte[] DecodeRecipient(string encoded)
    {
        ArgumentNullException.ThrowIfNull(encoded);

        return Decode(encoded, RecipientHrp);
    }

    private static byte[] Decode(string encoded, string expectedHrp)
    {
        var (hrp, words) = DecodeWords(encoded);

        if (string.Compare(hrp, expectedHrp, StringComparison.OrdinalIgnoreCase) != 0)
        {
            throw new AgeFormatException($"Invalid Bech32 HRP: expected '{expectedHrp}', got '{hrp}'");
        }

        var data = ConvertBits(words, 5, 8, false);
        return data;
    }

    internal static bool IsValidIdentity(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
        {
            return false;
        }

        try
        {
            var (hrp, _) = DecodeWords(encoded);
            return string.Compare(hrp, IdentityHrp, StringComparison.OrdinalIgnoreCase) == 0;
        }
        catch
        {
            return false;
        }
    }

    internal static bool IsValidRecipient(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
        {
            return false;
        }

        try
        {
            var (hrp, _) = DecodeWords(encoded);
            return string.Compare(hrp, RecipientHrp, StringComparison.OrdinalIgnoreCase) == 0;
        }
        catch
        {
            return false;
        }
    }

    private static string EncodeWords(string hrp, byte[] words)
    {
        var checksum = CreateChecksum(hrp.ToLowerInvariant(), words);
        var combined = new byte[words.Length + checksum.Length];
        Array.Copy(words, 0, combined, 0, words.Length);
        Array.Copy(checksum, 0, combined, words.Length, checksum.Length);

        var charset = hrp.Any(char.IsUpper) ? CharsetUpper : CharsetLower;

        var result = new StringBuilder();
        result.Append(hrp);
        result.Append('1');

        foreach (var value in combined)
        {
            result.Append(charset[value]);
        }

        return result.ToString();
    }

    private static (string hrp, byte[] words) DecodeWords(string encoded)
    {
        if (encoded.Length < 8)
        {
            throw new AgeFormatException("Bech32 string too short");
        }

        var pos = encoded.LastIndexOf('1');
        if (pos < 1)
        {
            throw new AgeFormatException("Bech32 string missing separator");
        }

        if (encoded.ToLowerInvariant() != encoded && encoded.ToUpperInvariant() != encoded)
        {
            throw new AgeFormatException("Bech32 string must be all uppercase or all lowercase");
        }

        var hrpOriginal = encoded[..pos];

        var hrpLower = hrpOriginal.ToLowerInvariant();
        var dataPart = encoded[(pos + 1)..].ToLowerInvariant();

        var hrp = hrpLower;
        if (hrp.Length == 0 || hrp.Length > MaxHrpLength)
        {
            throw new AgeFormatException("Invalid HRP length");
        }

        if (dataPart.Length < MinDataLength)
        {
            throw new AgeFormatException("Bech32 data too short");
        }

        var words = new byte[dataPart.Length];
        for (var i = 0; i < dataPart.Length; i++)
        {
            var c = dataPart[i];
            if (!CharsetValues.TryGetValue(c, out var value))
            {
                throw new AgeFormatException($"Invalid Bech32 character: '{c}'");
            }
            words[i] = (byte)value;
        }

        if (!VerifyChecksum(hrpLower, words))
        {
            throw new AgeFormatException("Invalid Bech32 checksum");
        }

        return (hrpOriginal, words[..^ChecksumLength]);
    }

    private static byte[] CreateChecksum(string hrp, byte[] data)
    {
        var values = ExpandHrp(hrp);
        var combined = new int[values.Length + data.Length + ChecksumLength];
        Array.Copy(values, 0, combined, 0, values.Length);
        for (var i = 0; i < data.Length; i++)
        {
            combined[values.Length + i] = data[i];
        }

        var polymod = PolynomialMod(combined) ^ 1;
        var result = new byte[ChecksumLength];

        for (var i = 0; i < ChecksumLength; i++)
        {
            result[i] = (byte)((polymod >> (5 * (ChecksumLength - 1 - i))) & 31);
        }

        return result;
    }

    private static bool VerifyChecksum(string hrp, byte[] data)
    {
        var values = ExpandHrp(hrp);
        var combined = new int[values.Length + data.Length];
        Array.Copy(values, 0, combined, 0, values.Length);
        for (var i = 0; i < data.Length; i++)
        {
            combined[values.Length + i] = data[i];
        }

        return PolynomialMod(combined) == 1;
    }

    private static int[] ExpandHrp(string hrp)
    {
        var result = new int[hrp.Length * 2 + 1];

        for (var i = 0; i < hrp.Length; i++)
        {
            result[i] = hrp[i] >> 5;
            result[i + hrp.Length + 1] = hrp[i] & 31;
        }

        return result;
    }

    private static int PolynomialMod(int[] values, bool useBech32m)
    {
        var generator = useBech32m
            ? new[] { 0x07f6e2a7, 0x03f6e2a7, 0x0ef6e2a7, 0x1cf6e2a7, 0x3cf6e2a7 }
            : Bech32Generator;

        var chk = 1;

        foreach (var value in values)
        {
            var top = (chk >> 25) & 31;
            chk = (chk & 0x1ffffff) << 5 ^ value;

            for (var i = 0; i < generator.Length; i++)
            {
                if (((top >> i) & 1) != 0)
                {
                    chk ^= generator[i];
                }
            }
        }

        return chk;
    }

    private static int PolynomialMod(int[] values) => PolynomialMod(values, false);

    private static byte[] ConvertBits(byte[] data, int fromBits, int toBits, bool pad)
    {
        var acc = 0;
        var bits = 0;
        var result = new List<byte>();
        var maxv = (1 << toBits) - 1;

        foreach (var value in data)
        {
            if ((value >> fromBits) != 0)
            {
                throw new AgeFormatException($"Invalid value for bit conversion: {value >> fromBits}");
            }

            acc = (acc << fromBits) | value;
            bits += fromBits;

            while (bits >= toBits)
            {
                bits -= toBits;
                result.Add((byte)((acc >> bits) & maxv));
            }
        }

        if (pad)
        {
            if (bits > 0)
            {
                result.Add((byte)((acc << (toBits - bits)) & maxv));
            }
        }
        else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0)
        {
            throw new AgeFormatException("Invalid bit conversion");
        }

        return result.ToArray();
    }
}
