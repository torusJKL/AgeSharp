using System.Security.Cryptography;

using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Headers;

namespace AgeSharp.Core.Keys;

internal sealed class ScryptIdentity : IIdentity, IIdentityStanzaUnwrapper
{
    private readonly string _passphrase;

    public ScryptIdentity(string passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);

        if (string.IsNullOrEmpty(passphrase))
        {
            throw new AgeKeyException("Passphrase cannot be empty");
        }

        if (passphrase.Length > 64)
        {
            throw new AgeKeyException("Passphrase cannot exceed 64 characters");
        }

        _passphrase = passphrase.Normalize(System.Text.NormalizationForm.FormC);
    }

    public RecipientType Type => RecipientType.Scrypt;

    public string ToIdentityString() => _passphrase;

    public string ToRecipientString() => _passphrase;

    public byte[]? Unwrap(ParsedStanza stanza)
    {
        var scryptStanza = ScryptStanza.TryParse(stanza);
        if (scryptStanza is null)
        {
            return null;
        }

        try
        {
            return scryptStanza.Unwrap(_passphrase);
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
