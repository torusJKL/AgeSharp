using System.Security.Cryptography;

using AgeSharp.Core.Keys;

namespace AgeSharp.Core;

/// <summary>
/// Provides methods for generating age encryption keys.
/// </summary>
public static class AgeKeyGenerator
{
    private const int KeySize = 32;

    /// <summary>
    /// Generates a new X25519 identity key pair.
    /// </summary>
    /// <returns>A new X25519 identity.</returns>
    public static IIdentity GenerateX25519Key()
    {
        var privateKey = new byte[KeySize];
        RandomNumberGenerator.Fill(privateKey);
        return new X25519Identity(privateKey);
    }

    /// <summary>
    /// Gets the recipient string for an identity.
    /// </summary>
    /// <param name="identity">The identity to get the recipient string for.</param>
    /// <returns>The recipient string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when identity is null.</exception>
    public static string GetRecipientString(IIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        return identity.ToRecipientString();
    }

    /// <summary>
    /// Parses an identity string and returns the corresponding identity.
    /// </summary>
    /// <param name="identityString">The identity string (e.g., AGE-SECRET-KEY-1...)</param>
    /// <returns>The identity.</returns>
    /// <exception cref="ArgumentNullException">Thrown when identityString is null.</exception>
    public static IIdentity ParseIdentity(string identityString)
    {
        ArgumentNullException.ThrowIfNull(identityString);

        var privateKey = AgeSharp.Core.Encoding.AgeBech32.DecodeIdentityToPrivateKey(identityString);
        return new X25519Identity(privateKey);
    }
}
