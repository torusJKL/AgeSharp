using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;

namespace AgeSharp.Core.Keys;

internal sealed class X25519Recipient : IRecipient
{
    private const int KeySize = 32;

    private readonly byte[] _publicKey;

    public X25519Recipient(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        if (publicKey.Length != KeySize)
        {
            throw new AgeKeyException($"X25519 public key must be {KeySize} bytes");
        }

        _publicKey = new byte[KeySize];
        Buffer.BlockCopy(publicKey, 0, _publicKey, 0, KeySize);
    }

    public RecipientType Type => RecipientType.X25519;

    public byte[] GetPublicKey() => _publicKey;

    public string ToRecipientString() => AgeBech32.EncodeRecipient(_publicKey);
}
