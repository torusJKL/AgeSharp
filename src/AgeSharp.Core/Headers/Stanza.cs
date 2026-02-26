using AgeSharp.Core.Encoding;

namespace AgeSharp.Core.Headers;

internal abstract class Stanza
{
    public abstract string Type { get; }

    public string[] Arguments { get; }

    public byte[] Body { get; }

    protected Stanza(string[] arguments, byte[] body)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(body);

        Arguments = arguments;
        Body = body;
    }

    private string GetArgumentLine()
    {
        var allArgs = new[] { Type }.Concat(Arguments).ToArray();
        return "-> " + string.Join(" ", allArgs);
    }

    private string GetBodyText()
    {
        return Base64NoPadding.Encode(Body);
    }

    private IEnumerable<string> GetWrappedBodyLines()
    {
        const int LineLength = 64;
        var bodyText = GetBodyText();

        if (bodyText.Length <= LineLength)
        {
            yield return bodyText;
            yield break;
        }

        var index = 0;
        while (index + LineLength < bodyText.Length)
        {
            yield return bodyText.Substring(index, LineLength);
            index += LineLength;
        }

        yield return bodyText[index..];
    }

    internal IEnumerable<string> GetStanzaLines()
    {
        yield return GetArgumentLine();

        foreach (var line in GetWrappedBodyLines())
        {
            yield return line;
        }
    }
}
