using System.Security.Cryptography;

using AgeSharp.Core.Headers;
using AgeSharp.Core.Payload;
using AgeSharp.Core.Exceptions;

namespace AgeSharp.Core;

/// <summary>
/// Provides methods for encrypting and decrypting data using the Age encryption format.
/// </summary>
public static class Age
{
    private const int FileKeySize = 16;

    /// <summary>
    /// Encrypts a stream of data to the specified recipients.
    /// </summary>
    /// <param name="input">The input stream to encrypt.</param>
    /// <param name="output">The output stream to write encrypted data to.</param>
    /// <param name="recipients">The recipients to encrypt for.</param>
    /// <param name="options">Optional encryption options.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <exception cref="ArgumentNullException">Thrown when input, output, or recipients is null.</exception>
    /// <exception cref="AgeEncryptionException">Thrown when encryption fails.</exception>
    public static async Task EncryptAsync(Stream input, Stream output, IEnumerable<IRecipient> recipients, EncryptionOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(recipients);

        options ??= new EncryptionOptions();

        var recipientList = recipients.ToList();
        if (recipientList.Count == 0)
        {
            throw new AgeEncryptionException("At least one recipient is required");
        }

        var fileKey = RandomNumberGenerator.GetBytes(FileKeySize);

        var stanzas = new List<Stanza>();
        foreach (var recipient in recipientList)
        {
            if (recipient is IRecipientStanzaFactory factory)
            {
                stanzas.Add(factory.CreateStanza(fileKey));
            }
            else
            {
                throw new AgeUnsupportedFeatureException($"Recipient type '{recipient.Type}' is not supported");
            }
        }

        var header = HeaderWriter.Write(stanzas, fileKey);

        using var memStream = new MemoryStream();
        var headerBytes = System.Text.Encoding.ASCII.GetBytes(header);
        await memStream.WriteAsync(headerBytes, cancellationToken);

        PayloadStream.WritePayload(input, memStream, fileKey, cancellationToken);

        var encryptedData = memStream.ToArray();

        if (options.Armor)
        {
            var armored = AgeArmor.Encode(encryptedData);
            var armoredBytes = System.Text.Encoding.ASCII.GetBytes(armored);
            await output.WriteAsync(armoredBytes, cancellationToken);
        }
        else
        {
            await output.WriteAsync(encryptedData, cancellationToken);
        }
    }

    /// <summary>
    /// Decrypts a stream of data using the provided identities.
    /// </summary>
    /// <param name="input">The input stream containing encrypted data.</param>
    /// <param name="output">The output stream to write decrypted data to.</param>
    /// <param name="identities">The identities to try for decryption.</param>
    /// <param name="options">Optional decryption options.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <exception cref="ArgumentNullException">Thrown when input, output, or identities is null.</exception>
    /// <exception cref="AgeDecryptionException">Thrown when decryption fails.</exception>
    public static async Task DecryptAsync(Stream input, Stream output, IEnumerable<IIdentity> identities, DecryptionOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(identities);

        var identityList = identities.ToList();
        if (identityList.Count == 0)
        {
            throw new AgeDecryptionException("At least one identity is required");
        }

        using var memStream = new MemoryStream();
        await input.CopyToAsync(memStream, cancellationToken);
        var allData = memStream.ToArray();

        if (AgeArmor.IsArmored(allData))
        {
            allData = AgeArmor.Decode(allData);
        }

        var headerEndIndex = FindHeaderEnd(allData);
        if (headerEndIndex < 0)
        {
            throw new AgeFormatException("Invalid age file: no header found");
        }

        var headerText = System.Text.Encoding.ASCII.GetString(allData, 0, headerEndIndex + 1);
        var (stanzas, _) = HeaderReader.Read(headerText);

        var fileKey = TryUnwrapFileKey(stanzas, identityList);
        if (fileKey is null)
        {
            throw new AgeIdentityNotFoundException("No matching identity found");
        }

        if (!HeaderReader.VerifyMac(headerText, fileKey))
        {
            throw new AgeDecryptionException("Header MAC verification failed");
        }

        var payloadData = new byte[allData.Length - headerEndIndex - 1];
        Buffer.BlockCopy(allData, headerEndIndex + 1, payloadData, 0, payloadData.Length);

        var payloadStream = new MemoryStream(payloadData);
        PayloadStream.ReadPayload(payloadStream, output, fileKey, cancellationToken);
    }

    private static int FindHeaderEnd(byte[] data)
    {
        var macLineIndex = data.AsSpan().IndexOf("\n--- "u8);
        if (macLineIndex < 0) return -1;

        var afterMacLine = data.AsSpan(macLineIndex + 1);
        var newlineIndex = afterMacLine.IndexOf((byte)'\n');
        return newlineIndex >= 0 ? macLineIndex + 1 + newlineIndex : -1;
    }

    /// <summary>
    /// Encrypts a byte array to the specified recipients.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="recipients">The recipients to encrypt for.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encrypted data.</returns>
    /// <exception cref="ArgumentNullException">Thrown when data or recipients is null.</exception>
    /// <exception cref="AgeEncryptionException">Thrown when encryption fails.</exception>
    public static async Task<byte[]> EncryptAsync(byte[] data, IEnumerable<IRecipient> recipients, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);

        using var input = new MemoryStream(data);
        using var output = new MemoryStream();
        await EncryptAsync(input, output, recipients, null, cancellationToken);
        return output.ToArray();
    }

    /// <summary>
    /// Decrypts a byte array using the provided identities.
    /// </summary>
    /// <param name="data">The encrypted data.</param>
    /// <param name="identities">The identities to try for decryption.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The decrypted data.</returns>
    /// <exception cref="ArgumentNullException">Thrown when data or identities is null.</exception>
    /// <exception cref="AgeDecryptionException">Thrown when decryption fails.</exception>
    public static async Task<byte[]> DecryptAsync(byte[] data, IEnumerable<IIdentity> identities, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);

        using var input = new MemoryStream(data);
        using var output = new MemoryStream();
        await DecryptAsync(input, output, identities, null, cancellationToken);
        return output.ToArray();
    }

    /// <summary>
    /// Attempts to encrypt a stream without throwing on failure.
    /// </summary>
    /// <param name="input">The input stream to encrypt.</param>
    /// <param name="output">The output stream to write encrypted data to.</param>
    /// <param name="recipients">The recipients to encrypt for.</param>
    /// <param name="options">Optional encryption options.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>True if encryption succeeded; otherwise, false.</returns>
    public static async Task<bool> TryEncryptAsync(Stream input, Stream output, IEnumerable<IRecipient> recipients, EncryptionOptions? options = null, CancellationToken cancellationToken = default)
    {
        try
        {
            await EncryptAsync(input, output, recipients, options, cancellationToken);
            return true;
        }
        catch (AgeException)
        {
            return false;
        }
    }

    /// <summary>
    /// Attempts to decrypt a stream without throwing on failure.
    /// </summary>
    /// <param name="input">The input stream containing encrypted data.</param>
    /// <param name="output">The output stream to write decrypted data to.</param>
    /// <param name="identities">The identities to try for decryption.</param>
    /// <param name="options">Optional decryption options.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>True if decryption succeeded; otherwise, false.</returns>
    public static async Task<bool> TryDecryptAsync(Stream input, Stream output, IEnumerable<IIdentity> identities, DecryptionOptions? options = null, CancellationToken cancellationToken = default)
    {
        try
        {
            await DecryptAsync(input, output, identities, options, cancellationToken);
            return true;
        }
        catch (AgeException)
        {
            return false;
        }
    }

    /// <summary>
    /// Attempts to encrypt a byte array without throwing on failure.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="recipients">The recipients to encrypt for.</param>
    /// <param name="encryptedData">The encrypted data if successful; otherwise, null.</param>
    /// <returns>True if encryption succeeded; otherwise, false.</returns>
    public static bool TryEncrypt(byte[] data, IEnumerable<IRecipient> recipients, out byte[]? encryptedData)
    {
        try
        {
            encryptedData = EncryptAsync(data, recipients, CancellationToken.None).GetAwaiter().GetResult();
            return true;
        }
        catch (AgeException)
        {
            encryptedData = null;
            return false;
        }
    }

    /// <summary>
    /// Attempts to decrypt a byte array without throwing on failure.
    /// </summary>
    /// <param name="data">The encrypted data.</param>
    /// <param name="identities">The identities to try for decryption.</param>
    /// <param name="decryptedData">The decrypted data if successful; otherwise, null.</param>
    /// <returns>True if decryption succeeded; otherwise, false.</returns>
    public static bool TryDecrypt(byte[] data, IEnumerable<IIdentity> identities, out byte[]? decryptedData)
    {
        try
        {
            decryptedData = DecryptAsync(data, identities, CancellationToken.None).GetAwaiter().GetResult();
            return true;
        }
        catch (AgeException)
        {
            decryptedData = null;
            return false;
        }
    }

    /// <summary>
    /// Attempts to encrypt a byte array and returns a tuple indicating success.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="recipients">The recipients to encrypt for.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A tuple containing success status and the encrypted data.</returns>
    public static async Task<(bool Success, byte[]? Data)> TryEncryptAsync(byte[] data, IEnumerable<IRecipient> recipients, CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await EncryptAsync(data, recipients, cancellationToken);
            return (true, result);
        }
        catch (AgeException)
        {
            return (false, null);
        }
    }

    /// <summary>
    /// Attempts to decrypt a byte array and returns a tuple indicating success.
    /// </summary>
    /// <param name="data">The encrypted data.</param>
    /// <param name="identities">The identities to try for decryption.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A tuple containing success status and the decrypted data.</returns>
    public static async Task<(bool Success, byte[]? Data)> TryDecryptAsync(byte[] data, IEnumerable<IIdentity> identities, CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await DecryptAsync(data, identities, cancellationToken);
            return (true, result);
        }
        catch (AgeException)
        {
            return (false, null);
        }
    }

    private static byte[]? TryUnwrapFileKey(List<ParsedStanza> stanzas, List<IIdentity> identities)
    {
        var identitiesByType = identities
            .OfType<IIdentityStanzaUnwrapper>()
            .GroupBy(i => i.Type.ToString())
            .ToDictionary(g => g.Key, g => g.ToList());

        foreach (var stanza in stanzas)
        {
            if (identitiesByType.TryGetValue(stanza.Type, out var matchingIdentities))
            {
                foreach (var identity in matchingIdentities)
                {
                    var fileKey = identity.Unwrap(stanza);
                    if (fileKey is not null)
                    {
                        return fileKey;
                    }
                }
            }
        }

        return null;
    }
}
