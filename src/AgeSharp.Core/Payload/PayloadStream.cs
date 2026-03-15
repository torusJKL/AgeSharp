using System.Security.Cryptography;

using AgeSharp.Core.Exceptions;

namespace AgeSharp.Core.Payload;

internal static class PayloadStream
{
    private const int ChunkSize = 64 * 1024;
    private const int PayloadNonceSize = 16;

    internal static (byte[] nonce, long payloadSize) WritePayload(Stream input, Stream output, byte[] fileKey, CancellationToken cancellationToken = default)
    {
        var nonce = RandomNumberGenerator.GetBytes(PayloadNonceSize);
        output.Write(nonce);
        
        var payloadKey = PayloadCrypter.DerivePayloadKey(fileKey, nonce);

        var chunkIndex = 0ul;
        var buffer = new byte[ChunkSize];
        int bytesRead;

        while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            var isFinal = bytesRead < ChunkSize;
            var plaintext = buffer[..bytesRead];
            var ciphertext = PayloadCrypter.EncryptChunk(plaintext, payloadKey, chunkIndex, isFinal);
            output.Write(ciphertext);
            
            chunkIndex++;
        }

        if (chunkIndex == 0)
        {
            var ciphertext = PayloadCrypter.EncryptChunk(Array.Empty<byte>(), payloadKey, 0, true);
            output.Write(ciphertext);
        }

        return (nonce, input.Length);
    }

    internal static void ReadPayload(Stream input, Stream output, byte[] fileKey, CancellationToken cancellationToken = default)
    {
        var nonce = new byte[PayloadNonceSize];
        input.ReadExactly(nonce);
        
        var payloadKey = PayloadCrypter.DerivePayloadKey(fileKey, nonce);

        var chunkIndex = 0ul;
        var buffer = new byte[ChunkSize + 16];
        var foundChunk = false;
        
        while (true)
        {
            var bytesRead = input.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0)
            {
                break;
            }

            foundChunk = true;

            if (bytesRead < 16)
            {
                throw new AgeDecryptionException("Invalid payload: no chunks found");
            }

            var ciphertextLength = bytesRead - 16;
            var ciphertextAndTag = buffer[..bytesRead];
            var isFinal = ciphertextLength < ChunkSize;
            
            byte[] plaintext;
            try
            {
                plaintext = PayloadCrypter.DecryptChunk(ciphertextAndTag, payloadKey, chunkIndex, isFinal);
            }
            catch (CryptographicException)
            {
                throw new AgeDecryptionException("Payload decryption failed.");
            }
            output.Write(plaintext);
            
            if (isFinal)
            {
                break;
            }
            
            chunkIndex++;
        }

        if (!foundChunk)
        {
            throw new AgeDecryptionException("Invalid payload: no chunks found");
        }
    }
}
