using System.Text;

using AgeSharp.Core.Exceptions;

namespace AgeSharp.Core.Encoding;

internal static class Base64WithPadding
{
    private static bool IsValidBase64Char(char c)
    {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '+' ||
               c == '/' ||
               c == '=';
    }

    internal static string Encode(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        return Convert.ToBase64String(data);
    }

    internal static byte[] Decode(string encoded)
    {
        ArgumentNullException.ThrowIfNull(encoded);

        if (encoded.Any(c => false == IsValidBase64Char(c)))
        {
            throw new AgeFormatException("Invalid Base64 character.");
        }

        if (encoded.Length % 4 != 0)
        {
            throw new AgeFormatException("Invalid Base64 length.");
        }

        try
        {
            return Convert.FromBase64String(encoded);
        }
        catch (FormatException)
        {
            throw new AgeFormatException("Invalid Base64 encoding.");
        }
    }
}
