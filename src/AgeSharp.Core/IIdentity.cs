using AgeSharp.Core.Headers;
using AgeSharp.Core.Keys;

namespace AgeSharp.Core;

/// <summary>
/// Represents an identity (private key) for age decryption.
/// </summary>
public interface IIdentity
{
    /// <summary>
    /// Returns the identity encoded as a string.
    /// </summary>
    /// <returns>The identity string (e.g., AGE-SECRET-KEY-1...)</returns>
    string ToIdentityString();

    /// <summary>
    /// Gets the type of the identity.
    /// </summary>
    RecipientType Type { get; }

    /// <summary>
    /// Returns the recipient (public key) derived from this identity.
    /// </summary>
    /// <returns>The recipient string.</returns>
    string ToRecipientString();
}

internal interface IIdentityStanzaUnwrapper : IIdentity
{
    byte[]? Unwrap(ParsedStanza stanza);
}
