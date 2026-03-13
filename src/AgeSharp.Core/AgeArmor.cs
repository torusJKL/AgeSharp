using System.Text;

using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;

namespace AgeSharp.Core;

internal static class AgeArmor
{
    private const string ArmorHeader = "-----BEGIN AGE ENCRYPTED FILE-----";
    private const string ArmorFooter = "-----END AGE ENCRYPTED FILE-----";
    private const int ColumnLimit = 64;

    internal static bool IsArmored(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (data.Length < ArmorHeader.Length)
        {
            return false;
        }

        var header = System.Text.Encoding.ASCII.GetString(data, 0, ArmorHeader.Length);
        return header == ArmorHeader;
    }

    internal static bool IsArmored(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        return text.Contains(ArmorHeader, StringComparison.Ordinal);
    }

    internal static string Encode(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        var base64 = Base64WithPadding.Encode(data);
        var wrapped = WrapAtColumn(base64, ColumnLimit);
        return $"{ArmorHeader}\n{wrapped}{ArmorFooter}\n";
    }

    internal static byte[] Decode(string armored)
    {
        ArgumentNullException.ThrowIfNull(armored);

        var headerIndex = armored.IndexOf(ArmorHeader, StringComparison.Ordinal);
        if (headerIndex < 0)
        {
            throw new AgeFormatException("Invalid armored file: missing header");
        }

        var footerIndex = armored.IndexOf(ArmorFooter, StringComparison.Ordinal);
        if (footerIndex < 0)
        {
            throw new AgeFormatException("Invalid armored file: missing footer");
        }

        if (footerIndex <= headerIndex + ArmorHeader.Length)
        {
            throw new AgeFormatException("Invalid armored file: footer before header");
        }

        var base64Start = headerIndex + ArmorHeader.Length;
        var base64Text = armored.Substring(base64Start, footerIndex - base64Start);

        base64Text = base64Text.Trim();
        base64Text = base64Text.Replace("\n", "").Replace("\r", "").Replace(" ", "");

        if (base64Text.Length == 0)
        {
            throw new AgeFormatException("Invalid armored file: empty body");
        }

        return Base64WithPadding.Decode(base64Text);
    }

    internal static byte[] Decode(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        var text = System.Text.Encoding.ASCII.GetString(data);
        return Decode(text);
    }

    private static string WrapAtColumn(string text, int columnLimit)
    {
        if (text.Length <= columnLimit)
        {
            return text + "\n";
        }

        var result = new StringBuilder();

        for (int i = 0; i < text.Length; i += columnLimit)
        {
            int len = Math.Min(columnLimit, text.Length - i);
            result.Append(text, i, len);
            result.Append('\n');
        }

        return result.ToString();
    }
}
