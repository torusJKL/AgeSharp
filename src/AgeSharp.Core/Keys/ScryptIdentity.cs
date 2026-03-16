using System.Security.Cryptography;

using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Headers;

namespace AgeSharp.Core.Keys;

/// <summary>
/// Stores passphrase as byte[] rather than string to allow secure memory zeroing after use.
/// Strings in .NET are immutable and cannot be overwritten in memory, making them difficult to securely erase.
/// </summary>
internal sealed class ScryptIdentity : IIdentity, IIdentityStanzaUnwrapper
{
    private readonly byte[] _passphrase;

    internal ScryptIdentity(string passphrase)
    {
        _passphrase = PassphraseValidator.ValidateAndNormalizeToBytes(passphrase);
    }

    public RecipientType Type => RecipientType.Scrypt;

    public string ToIdentityString() 
        => throw new NotSupportedException("Cannot serialize passphrase identity");

    public string ToRecipientString() 
        => throw new NotSupportedException("Cannot serialize passphrase identity");

    public byte[]? Unwrap(ParsedStanza stanza)
    {
        var scryptStanza = ScryptStanza.TryParse(stanza);
        if (scryptStanza is null)
        {
            return null;
        }

        try
        {
            var result = scryptStanza.Unwrap(_passphrase);
            CryptographicOperations.ZeroMemory(_passphrase);
            return result;
        }
        catch (AgeFormatException)
        {
            throw;
        }
        catch (CryptographicException)
        {
            throw new AgeInvalidPassphraseException();
        }
    }
}
