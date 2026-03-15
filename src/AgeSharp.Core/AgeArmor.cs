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

        var maxHeaderLength = ArmorHeader.Length;
        if (data.Length < maxHeaderLength)
        {
            return false;
        }

        var startIndex = 0;
        while (startIndex < data.Length && (data[startIndex] == ' ' || data[startIndex] == '\t' || data[startIndex] == '\r' || data[startIndex] == '\n'))
        {
            startIndex++;
        }

        if (data.Length - startIndex < 5)
        {
            return false;
        }

        var afterDashes = startIndex;
        var hasDashesAtStart = true;
        for (var i = 0; i < 5; i++)
        {
            if (data[afterDashes + i] != '-')
            {
                hasDashesAtStart = false;
                break;
            }
        }

        if (!hasDashesAtStart)
        {
            for (var j = 0; j < Math.Min(data.Length - 4, 100); j++)
            {
                if (data[j] == '-' && data[j + 1] == '-' && data[j + 2] == '-' && data[j + 3] == '-' && data[j + 4] == '-')
                {
                    throw new AgeFormatException("Invalid armor: missing header dashes");
                }
            }
            return false;
        }

        afterDashes += 5;
        while (afterDashes < data.Length && (data[afterDashes] == ' ' || data[afterDashes] == '\t'))
        {
            afterDashes++;
        }

        if (data.Length - afterDashes < maxHeaderLength - 5)
        {
            return false;
        }

        var headerStart = afterDashes;
        if (data.Length - headerStart >= ArmorHeader.Length - 5)
        {
            var headerBytes = new Span<byte>(data, headerStart, ArmorHeader.Length - 5);
            var matches = true;
            for (var i = 0; i < ArmorHeader.Length - 5; i++)
            {
                var b = headerBytes[i];
                var d = (byte)ArmorHeader[i + 5];
                if (d >= 'A' && d <= 'Z') matches = matches && (b == d);
                else if (d >= 'a' && d <= 'z') matches = matches && (b == d || b == d - 32);
                else matches = matches && (b == d);
            }
            if (matches)
            {
                return true;
            }
        }

        throw new AgeFormatException("Invalid armor: no valid header found");
    }

    internal static bool IsArmored(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var result = FindHeaderPosition(text);
        return result.found;
    }

    private static (bool found, int index) FindHeaderPosition(string text)
    {
        var startIndex = 0;
        while (startIndex < text.Length && (text[startIndex] == ' ' || text[startIndex] == '\t' || text[startIndex] == '\r' || text[startIndex] == '\n'))
        {
            startIndex++;
        }

        if (text.Length - startIndex >= ArmorHeader.Length)
        {
            var match = true;
            for (var i = 0; i < ArmorHeader.Length; i++)
            {
                var t = text[startIndex + i];
                var h = ArmorHeader[i];
                if (h >= 'A' && h <= 'Z') match = match && (t == h);
                else if (h >= 'a' && h <= 'z') match = match && (t == h || t == h - 32);
                else match = match && (t == h);
            }
            if (match)
            {
                return (true, startIndex);
            }
        }

        return (false, -1);
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

        var headerResult = FindHeaderPosition(armored);
        if (!headerResult.found)
        {
            throw new AgeFormatException("Invalid armored file: missing header");
        }

        var headerIndex = headerResult.index;
        var idx = armored.IndexOf(ArmorFooter, headerIndex + ArmorHeader.Length, StringComparison.Ordinal);
        int footerIndex = idx >= 0 ? idx : -1;

        if (footerIndex < 0)
        {
            throw new AgeFormatException("Invalid armored file: missing footer");
        }

        if (footerIndex <= headerIndex + ArmorHeader.Length)
        {
            throw new AgeFormatException("Invalid armored file: footer before header");
        }

        var trailingContent = armored[(footerIndex + ArmorFooter.Length)..];
        foreach (var c in trailingContent)
        {
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
            {
                throw new AgeFormatException("Invalid armored file: garbage after footer");
            }
        }

        var bodyStart = headerIndex + ArmorHeader.Length;
        var bodySection = armored.Substring(bodyStart, footerIndex - bodyStart);

        var hasNonWhitespace = false;
        foreach (var c in bodySection)
        {
            if (c != '\n' && c != '\r' && c != ' ')
            {
                hasNonWhitespace = true;
                break;
            }
        }

        if (!hasNonWhitespace)
        {
            throw new AgeFormatException("Invalid armored file: empty body");
        }

        var lines = bodySection.Split('\n', StringSplitOptions.None);
        var lastNonEmpty = -1;
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            if (line.Length > 0)
            {
                lastNonEmpty = i;
            }
        }

        for (var i = 1; i < lines.Length - 1; i++)
        {
            var line = lines[i].TrimEnd('\r');
            if (line.Length == 0)
            {
                throw new AgeFormatException("Invalid armored file: empty line in body");
            }
        }

        for (var i = 0; i <= lastNonEmpty; i++)
        {
            var lineOriginal = lines[i];
            var line = lineOriginal.TrimEnd('\r');
            if (line.Length > 0)
            {
                var lineTrimmed = line.TrimEnd();
                if (lineTrimmed.Length != line.Length)
                {
                    throw new AgeFormatException("Invalid armored file: trailing whitespace in line");
                }
                line = lineTrimmed;
            }

            if (line.Length == 0)
            {
                continue;
            }

            if (i < lastNonEmpty && line.Length < ColumnLimit)
            {
                throw new AgeFormatException("Invalid armored file: line too short");
            }

            if (line.Length > ColumnLimit)
            {
                throw new AgeFormatException("Invalid armored file: line too long");
            }
        }

        var base64Text = bodySection;
        base64Text = base64Text.Trim();
        base64Text = base64Text.Replace("\n", "").Replace("\r", "").Replace(" ", "");

        if (base64Text.Length == 0)
        {
            throw new AgeFormatException("Invalid armored file: empty body");
        }

        var normalizedBase64 = base64Text.Replace("=", "");
        var decoded = Base64WithPadding.Decode(base64Text);

        var headerEndIndex = FindHeaderEndIndex(decoded);
        if (headerEndIndex > 0)
        {
            var headerBytes = decoded.AsSpan(0, headerEndIndex + 1);
            var headerText = System.Text.Encoding.ASCII.GetString(headerBytes);
            Headers.HeaderReader.ValidateLineEndings(headerText);
        }

        var reencoded = Base64NoPadding.Encode(decoded);
        if (reencoded != normalizedBase64)
        {
            throw new AgeFormatException("Invalid armored file: base64 not canonical");
        }

        return decoded;
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

    private static int FindHeaderEndIndex(byte[] data)
    {
        var macLineIndex = data.AsSpan().IndexOf("\n--- "u8);
        if (macLineIndex < 0) return -1;

        var afterMacLine = data.AsSpan(macLineIndex + 1);
        var newlineIndex = afterMacLine.IndexOf((byte)'\n');
        return newlineIndex >= 0 ? macLineIndex + newlineIndex : -1;
    }
}
