namespace AgeSharp.Core.Keys;

/// <summary>
/// Specifies the type of recipient or identity.
/// </summary>
public enum RecipientType
{
    /// <summary>
    /// X25519 key exchange.
    /// </summary>
    X25519,

    /// <summary>
    /// Scrypt passphrase-based key derivation.
    /// </summary>
    Scrypt,
}
