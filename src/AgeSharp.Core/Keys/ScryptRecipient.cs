using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Headers;

namespace AgeSharp.Core.Keys;

internal sealed class ScryptRecipient : IRecipient, IRecipientStanzaFactory
{
    private readonly string _passphrase;

    public ScryptRecipient(string passphrase)
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

    public string ToRecipientString() => _passphrase;

    public Stanza CreateStanza(byte[] fileKey)
    {
        return ScryptStanza.Create(fileKey, _passphrase);
    }
}
