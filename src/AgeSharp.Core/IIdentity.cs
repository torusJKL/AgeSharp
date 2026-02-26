using AgeSharp.Core.Keys;

namespace AgeSharp.Core;

/// <summary>
/// Represents an identity (private key) for age encryption.
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
}
