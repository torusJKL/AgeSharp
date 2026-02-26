using System.Security.Cryptography;

using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;
using NSec.Cryptography;

namespace AgeSharp.Core.Keys;

internal sealed class X25519Identity : IIdentity
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

    public X25519Recipient ToRecipient() => new(GetPublicKey());
}
