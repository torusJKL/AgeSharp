using System.Text;

using AgeSharp.Core.Exceptions;

namespace AgeSharp.Core.Keys;

internal static class PassphraseValidator
{
    internal const int MaxPassphraseLength = 64;
    internal const int MinLogN = 1;
    internal const int MaxLogN = 22;
    internal const string PassphraseCannotBeEmpty = "Passphrase cannot be empty";

    internal static string PassphraseExceedsMaxLength => $"Passphrase cannot exceed {MaxPassphraseLength} characters";

    /// <summary>
    /// Validates and normalizes a passphrase, then converts to bytes for secure handling.
    /// Returns byte[] instead of string to allow secure memory zeroing after use.
    /// </summary>
    internal static byte[] ValidateAndNormalizeToBytes(string passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);

        if (string.IsNullOrWhiteSpace(passphrase))
        {
            throw new AgeKeyException(PassphraseCannotBeEmpty);
        }

        var normalized = passphrase.Normalize(System.Text.NormalizationForm.FormC);

        if (normalized.Length > MaxPassphraseLength)
        {
            throw new AgeKeyException(PassphraseExceedsMaxLength);
        }

        var passphraseBytes = new UTF8Encoding(false).GetBytes(normalized);

        return passphraseBytes;
    }

    internal static void ValidateLogN(int logN)
    {
        if (logN < MinLogN)
        {
            throw new AgeFormatException($"Scrypt logN below minimum allowed value of {MinLogN}");
        }

        if (logN > MaxLogN)
        {
            throw new AgeFormatException($"Scrypt logN exceeds maximum allowed value of {MaxLogN}");
        }
    }
}
