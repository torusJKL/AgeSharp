using AgeSharp.Core.Keys;

namespace AgeSharp.Core;

/// <summary>
/// Represents a recipient (public key) for age encryption.
/// </summary>
public interface IRecipient
{
    /// <summary>
    /// Returns the recipient encoded as a string.
    /// </summary>
    /// <returns>The recipient string (e.g., age1...)</returns>
    string ToRecipientString();

    /// <summary>
    /// Gets the type of the recipient.
    /// </summary>
    RecipientType Type { get; }
}
