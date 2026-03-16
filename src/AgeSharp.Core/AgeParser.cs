using AgeSharp.Core.Encoding;
using AgeSharp.Core.Keys;
using AgeSharp.Core.Exceptions;

namespace AgeSharp.Core;

/// <summary>
/// Provides methods for parsing recipient and identity strings.
/// </summary>
public static class AgeParser
{
    /// <summary>
    /// Parses a recipient string into an IRecipient.
    /// </summary>
    /// <param name="input">The recipient string (e.g., age1...) or passphrase.</param>
    /// <returns>The parsed recipient.</returns>
    /// <exception cref="ArgumentNullException">Thrown when input is null.</exception>
    /// <exception cref="AgeKeyException">Thrown when input is not a valid recipient string.</exception>
    public static IRecipient ParseRecipient(string input)
    {
        ArgumentNullException.ThrowIfNull(input);

        input = input.Trim();

        if (AgeBech32.IsValidRecipient(input))
        {
            var publicKey = AgeBech32.DecodeRecipient(input);
            return new X25519Recipient(publicKey);
        }

        if (!string.IsNullOrEmpty(input))
        {
            return new ScryptRecipient(input);
        }

        throw new AgeKeyException($"Invalid recipient string: {input}");
    }

    /// <summary>
    /// Parses an identity string into an IIdentity.
    /// </summary>
    /// <param name="input">The identity string (e.g., AGE-SECRET-KEY-1...) or passphrase.</param>
    /// <returns>The parsed identity.</returns>
    /// <exception cref="ArgumentNullException">Thrown when input is null.</exception>
    /// <exception cref="AgeKeyException">Thrown when input is not a valid identity string.</exception>
    public static IIdentity ParseIdentity(string input)
    {
        ArgumentNullException.ThrowIfNull(input);

        input = input.Trim();

        if (AgeBech32.IsValidIdentity(input))
        {
            var privateKey = AgeBech32.DecodeIdentity(input);
            return new X25519Identity(privateKey);
        }

        if (!string.IsNullOrEmpty(input))
        {
            return new ScryptIdentity(input);
        }

        throw new AgeKeyException($"Invalid identity string: {input}");
    }

    /// <summary>
    /// Parses a recipients file, returning all valid recipients found.
    /// </summary>
    /// <param name="path">The path to the recipients file.</param>
    /// <returns>An enumerable of recipients parsed from the file.</returns>
    /// <exception cref="ArgumentNullException">Thrown when path is null.</exception>
    /// <exception cref="AgeKeyException">Thrown when a line in the file is not a valid recipient.</exception>
    public static IEnumerable<IRecipient> ParseRecipientsFile(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        var lines = File.ReadAllLines(path);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith('#'))
            {
                continue;
            }

            yield return ParseRecipient(trimmed);
        }
    }

    /// <summary>
    /// Parses an identities file, returning all valid identities found.
    /// </summary>
    /// <param name="path">The path to the identities file.</param>
    /// <returns>An enumerable of identities parsed from the file.</returns>
    /// <exception cref="ArgumentNullException">Thrown when path is null.</exception>
    /// <exception cref="AgeKeyException">Thrown when a line in the file is not a valid identity.</exception>
    public static IEnumerable<IIdentity> ParseIdentitiesFile(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        var lines = File.ReadAllLines(path);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith('#'))
            {
                continue;
            }

            yield return ParseIdentity(trimmed);
        }
    }
}
