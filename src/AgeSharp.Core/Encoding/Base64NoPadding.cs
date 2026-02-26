using System.Text;

using AgeSharp.Core.Exceptions;

namespace AgeSharp.Core.Encoding;

internal static class Base64NoPadding
{
    private static bool IsValidBase64Char(char c)
    {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '+' ||
               c == '/';
    }

    internal static string Encode(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        return Convert.ToBase64String(data).TrimEnd('=');
    }

    internal static byte[] Decode(string encoded)
    {
        ArgumentNullException.ThrowIfNull(encoded);

        if (encoded.Contains('='))
        {
            throw new AgeFormatException("Base64 must not contain padding characters ('=').");
        }

        if (encoded.Length % 4 == 1)
        {
            throw new AgeFormatException("Invalid Base64 length.");
        }

        if (!encoded.All(IsValidBase64Char))
        {
            throw new AgeFormatException("Invalid Base64 character.");
        }

        var padded = encoded.PadRight((encoded.Length + 3) / 4 * 4, '=');
        return Convert.FromBase64String(padded);
    }
}
