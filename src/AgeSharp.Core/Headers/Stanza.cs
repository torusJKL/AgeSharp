using AgeSharp.Core.Encoding;

namespace AgeSharp.Core.Headers;

/// <summary>
/// Represents a stanza in an age file header.
/// </summary>
public abstract class Stanza
{
    /// <summary>
    /// Gets the type of the stanza.
    /// </summary>
    public abstract string Type { get; }

    /// <summary>
    /// Gets the arguments of the stanza.
    /// </summary>
    public string[] Arguments { get; }

    /// <summary>
    /// Gets the body of the stanza.
    /// </summary>
    public byte[] Body { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Stanza"/> class.
    /// </summary>
    /// <param name="arguments">The stanza arguments.</param>
    /// <param name="body">The stanza body.</param>
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
