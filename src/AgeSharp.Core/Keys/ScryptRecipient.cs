using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Headers;

namespace AgeSharp.Core.Keys;

/// <summary>
/// Stores passphrase as byte[] rather than string to allow secure memory zeroing after use.
/// Strings in .NET are immutable and cannot be overwritten in memory, making them difficult to securely erase.
/// </summary>
internal sealed class ScryptRecipient : IRecipient, IRecipientStanzaFactory
{
    private readonly byte[] _passphrase;

    internal ScryptRecipient(string passphrase)
    {
        _passphrase = PassphraseValidator.ValidateAndNormalizeToBytes(passphrase);
    }

    public RecipientType Type => RecipientType.Scrypt;

    public string ToRecipientString() 
        => throw new NotSupportedException("Cannot serialize passphrase identity");

    public Stanza CreateStanza(byte[] fileKey)
    {
        try
        {
            return ScryptStanza.Create(fileKey, _passphrase);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(_passphrase);
        }
    }
}
