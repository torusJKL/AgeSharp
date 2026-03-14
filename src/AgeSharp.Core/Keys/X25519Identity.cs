using System.Security.Cryptography;

using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Headers;
using NSec.Cryptography;

namespace AgeSharp.Core.Keys;

internal sealed class X25519Identity : IIdentity, IIdentityStanzaUnwrapper
{
    private const int KeySize = 32;

    private readonly byte[] _privateKey;

    public X25519Identity(byte[] privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        if (privateKey.Length != KeySize)
        {
            throw new AgeKeyException($"X25519 private key must be {KeySize} bytes");
        }

        _privateKey = new byte[KeySize];
        Buffer.BlockCopy(privateKey, 0, _privateKey, 0, KeySize);
    }

    public RecipientType Type => RecipientType.X25519;

    public byte[] GetPrivateKey() => _privateKey;

    public byte[] GetPublicKey()
    {
        var key = Key.Import(KeyAgreementAlgorithm.X25519, _privateKey, KeyBlobFormat.RawPrivateKey);
        return key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }

    public string ToIdentityString() => AgeBech32.EncodeIdentity(_privateKey);

    public string ToRecipientString() => ToRecipient().ToRecipientString();

    public X25519Recipient ToRecipient() => new(GetPublicKey());

    public byte[]? Unwrap(ParsedStanza stanza)
    {
        if (stanza.Type != "X25519")
        {
            return null;
        }

        try
        {
            var x25519Stanza = new X25519Stanza(
                Base64NoPadding.Decode(stanza.Arguments[0]),
                stanza.Body);
            return x25519Stanza.Unwrap(_privateKey);
        }
        catch
        {
            return null;
        }
    }
}
