using System.Security.Cryptography;

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

        return (nonce, input.Length);
    }

    internal static void ReadPayload(Stream input, Stream output, byte[] fileKey, CancellationToken cancellationToken = default)
    {
        var nonce = new byte[PayloadNonceSize];
        input.ReadExactly(nonce);
        
        var payloadKey = PayloadCrypter.DerivePayloadKey(fileKey, nonce);

        var chunkIndex = 0ul;
        var buffer = new byte[ChunkSize + 16];
        
        while (true)
        {
            var bytesRead = input.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0)
            {
                break;
            }

            if (bytesRead < 16)
            {
                throw new Exception("Invalid chunk");
            }

            var ciphertextLength = bytesRead - 16;
            var ciphertextAndTag = buffer[..bytesRead];
            var isFinal = ciphertextLength < ChunkSize;
            
            var plaintext = PayloadCrypter.DecryptChunk(ciphertextAndTag, payloadKey, chunkIndex, isFinal);
            output.Write(plaintext);
            
            if (isFinal)
            {
                break;
            }
            
            chunkIndex++;
        }
    }
}
