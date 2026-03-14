using System.Security.Cryptography;

using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;
using NSec.Cryptography;

namespace AgeSharp.Core.Headers;

internal sealed class X25519Stanza : Stanza
{
    private const string StanzaType = "X25519";
    private const int RecipientKeySize = 32;
    private const int FileKeySize = 16;
    private const int NonceSize = 12;

    private readonly byte[] _ephemeralShare;

    internal X25519Stanza(byte[] ephemeralShare, byte[] body)
        : base([Base64NoPadding.Encode(ephemeralShare)], body)
    {
        _ephemeralShare = ephemeralShare;
    }

    public override string Type => StanzaType;

    private byte[] GetEphemeralShare() => _ephemeralShare;

    internal static X25519Stanza Create(byte[] fileKey, byte[] recipientPublicKey)
    {
        ArgumentNullException.ThrowIfNull(fileKey);
        ArgumentNullException.ThrowIfNull(recipientPublicKey);

        if (fileKey.Length != FileKeySize)
        {
            throw new ArgumentException($"File key must be {FileKeySize} bytes");
        }

        if (recipientPublicKey.Length != RecipientKeySize)
        {
            throw new ArgumentException($"Recipient public key must be {RecipientKeySize} bytes");
        }

        var ephemeralSecret = RandomNumberGenerator.GetBytes(RecipientKeySize);
        var ephemeralShare = X25519PublicKey(ephemeralSecret);
        using var sharedSecret = X25519SharedSecret(ephemeralSecret, recipientPublicKey);

        var salt = new byte[ephemeralShare.Length + recipientPublicKey.Length];
        Buffer.BlockCopy(ephemeralShare, 0, salt, 0, ephemeralShare.Length);
        Buffer.BlockCopy(recipientPublicKey, 0, salt, ephemeralShare.Length, recipientPublicKey.Length);

        var wrapKey = DeriveKey(sharedSecret, salt);

        var nonce = new byte[NonceSize];
        var body = EncryptWithKey(wrapKey, fileKey, nonce);

        return new X25519Stanza(ephemeralShare, body);
    }

    internal byte[] Unwrap(byte[] privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        if (privateKey.Length != RecipientKeySize)
        {
            throw new ArgumentException($"Private key must be {RecipientKeySize} bytes");
        }

        if (Body.Length != 32)
        {
            throw new AgeFormatException("X25519 body must be exactly 32 bytes");
        }

        var ephemeralShare = _ephemeralShare;
        using var sharedSecret = X25519SharedSecret(privateKey, ephemeralShare);

        var recipientPublicKey = X25519PublicKey(privateKey);
        var salt = new byte[ephemeralShare.Length + recipientPublicKey.Length];
        Buffer.BlockCopy(ephemeralShare, 0, salt, 0, ephemeralShare.Length);
        Buffer.BlockCopy(recipientPublicKey, 0, salt, ephemeralShare.Length, recipientPublicKey.Length);

        var wrapKey = DeriveKey(sharedSecret, salt);

        if (wrapKey.All(b => b == 0))
        {
            throw new AgeException("Shared secret is all zeros");
        }

        var nonce = new byte[NonceSize];
        return DecryptWithKey(wrapKey, Body, nonce);
    }

    private static byte[] DeriveKey(SharedSecret sharedSecret, byte[] salt)
    {
        var hkdf = new HkdfSha256();
        return hkdf.DeriveBytes(sharedSecret, salt, "age-encryption.org/v1/X25519"u8, 32);
    }

    private static byte[] X25519(byte[] scalar, byte[] point)
    {
        using var sharedSecret = X25519SharedSecret(scalar, point);
        return sharedSecret.Export(SharedSecretBlobFormat.RawSharedSecret);
    }

    private static SharedSecret X25519SharedSecret(byte[] scalar, byte[] point)
    {
        var privateKey = Key.Import(KeyAgreementAlgorithm.X25519, scalar, KeyBlobFormat.RawPrivateKey);
        var publicKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, point, KeyBlobFormat.RawPublicKey);
        var result = KeyAgreementAlgorithm.X25519.Agree(privateKey, publicKey);
        return result ?? throw new InvalidOperationException("Key agreement failed");
    }

    private static byte[] X25519PublicKey(byte[] privateKey)
    {
        var key = Key.Import(KeyAgreementAlgorithm.X25519, privateKey, KeyBlobFormat.RawPrivateKey);
        return key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }

    private static byte[] EncryptWithKey(byte[] key, byte[] plaintext, byte[] nonce)
    {
        using var chacha = new System.Security.Cryptography.ChaCha20Poly1305(key);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        chacha.Encrypt(nonce, plaintext, ciphertext, tag);

        var result = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, ciphertext.Length, tag.Length);
        return result;
    }

    private static byte[] DecryptWithKey(byte[] key, byte[] ciphertextAndTag, byte[] nonce)
    {
        const int TagSize = 16;

        if (ciphertextAndTag.Length < TagSize)
        {
            throw new ArgumentException("Ciphertext too short");
        }

        var ciphertextLength = ciphertextAndTag.Length - TagSize;
        var ciphertext = new byte[ciphertextLength];
        var tag = new byte[TagSize];
        Buffer.BlockCopy(ciphertextAndTag, 0, ciphertext, 0, ciphertextLength);
        Buffer.BlockCopy(ciphertextAndTag, ciphertextLength, tag, 0, TagSize);

        using var chacha = new System.Security.Cryptography.ChaCha20Poly1305(key);
        var plaintext = new byte[ciphertextLength];
        chacha.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}
