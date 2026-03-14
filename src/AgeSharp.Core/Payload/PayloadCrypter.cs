using System.Security.Cryptography;

namespace AgeSharp.Core.Payload;

internal static class PayloadCrypter
{
    private const int ChunkCounterSize = 11;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    internal static byte[] DerivePayloadKey(byte[] fileKey, byte[] nonce)
    {
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, fileKey, 32, nonce, "payload"u8.ToArray());
    }

    internal static byte[] ConstructNonce(ulong chunkIndex, bool isFinal)
    {
        var nonce = new byte[NonceSize];

        var counterBytes = new byte[ChunkCounterSize];
        var counter = chunkIndex;
        for (var i = ChunkCounterSize - 1; i >= 0; i--)
        {
            counterBytes[i] = (byte)(counter & 0xFF);
            counter >>= 8;
        }

        Buffer.BlockCopy(counterBytes, 0, nonce, 0, ChunkCounterSize);
        nonce[NonceSize - 1] = isFinal ? (byte)0x01 : (byte)0x00;

        return nonce;
    }

    internal static byte[] EncryptChunk(byte[] plaintext, byte[] payloadKey, ulong chunkIndex, bool isFinal)
    {
        var nonce = ConstructNonce(chunkIndex, isFinal);
        using var chacha = new ChaCha20Poly1305(payloadKey);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        chacha.Encrypt(nonce, plaintext, ciphertext, tag);

        var result = new byte[plaintext.Length + TagSize];
        Buffer.BlockCopy(ciphertext, 0, result, 0, plaintext.Length);
        Buffer.BlockCopy(tag, 0, result, plaintext.Length, TagSize);
        
        return result;
    }

    internal static byte[] DecryptChunk(byte[] ciphertextAndTag, byte[] payloadKey, ulong chunkIndex, bool isFinal)
    {
        if (ciphertextAndTag.Length < TagSize)
        {
            throw new ArgumentException("Ciphertext too short", nameof(ciphertextAndTag));
        }

        var nonce = ConstructNonce(chunkIndex, isFinal);
        var ciphertextLength = ciphertextAndTag.Length - TagSize;
        var ciphertext = new byte[ciphertextLength];
        var tag = new byte[TagSize];

        Buffer.BlockCopy(ciphertextAndTag, 0, ciphertext, 0, ciphertextLength);
        Buffer.BlockCopy(ciphertextAndTag, ciphertextLength, tag, 0, TagSize);

        using var chacha = new ChaCha20Poly1305(payloadKey);
        var plaintext = new byte[ciphertextLength];
        chacha.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }
}
