using System.Security.Cryptography;

using AgeSharp.Core;
using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Keys;
using Xunit;

namespace AgeSharp.Tests;

public class AgeTests
{
    [Fact]
    public async Task Encrypt_Decrypt_ReturnsOriginalData()
    {
        var originalData = "Hello, World! This is a test message."u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        var encrypted = await Age.EncryptAsync(originalData, [recipient]);
        var decrypted = await Age.DecryptAsync(encrypted, [identity]);

        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    public async Task EncryptAsync_Stream_DecryptAsync_Stream_Roundtrip()
    {
        var originalData = "Stream test data for encryption and decryption"u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        using var input = new MemoryStream(originalData);
        using var encryptedStream = new MemoryStream();
        await Age.EncryptAsync(input, encryptedStream, [recipient]);

        encryptedStream.Position = 0;
        using var decryptedStream = new MemoryStream();
        await Age.DecryptAsync(encryptedStream, decryptedStream, [identity]);

        Assert.Equal(originalData, decryptedStream.ToArray());
    }

    [Fact]
    public async Task Encrypt_MultipleRecipients_AllCanDecrypt()
    {
        var originalData = "Multi-recipient test"u8.ToArray();
        var identity1 = AgeKeyGenerator.GenerateX25519Key();
        var identity2 = AgeKeyGenerator.GenerateX25519Key();
        var recipient1 = AgeParser.ParseRecipient(identity1.ToRecipientString());
        var recipient2 = AgeParser.ParseRecipient(identity2.ToRecipientString());

        var encrypted = await Age.EncryptAsync(originalData, [recipient1, recipient2]);

        var decrypted1 = await Age.DecryptAsync(encrypted, [identity1]);
        var decrypted2 = await Age.DecryptAsync(encrypted, [identity2]);

        Assert.Equal(originalData, decrypted1);
        Assert.Equal(originalData, decrypted2);
    }

    [Fact]
    public async Task Decrypt_WrongIdentity_ThrowsAgeIdentityNotFoundException()
    {
        var originalData = "Secret message"u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var wrongIdentity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        var encrypted = await Age.EncryptAsync(originalData, [recipient]);

        await Assert.ThrowsAsync<AgeIdentityNotFoundException>(
            () => Age.DecryptAsync(encrypted, [wrongIdentity]));
    }

    [Fact]
    public async Task Decrypt_InvalidHeader_ThrowsAgeFormatException()
    {
        var invalidData = "This is not a valid age file"u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();

        await Assert.ThrowsAsync<AgeFormatException>(
            () => Age.DecryptAsync(invalidData, [identity]));
    }

    [Fact]
    public async Task Encrypt_EmptyRecipients_ThrowsAgeEncryptionException()
    {
        var originalData = "Test data"u8.ToArray();

        await Assert.ThrowsAsync<AgeEncryptionException>(
            () => Age.EncryptAsync(originalData, Array.Empty<IRecipient>()));
    }

    [Fact]
    public async Task Decrypt_EmptyIdentities_ThrowsAgeDecryptionException()
    {
        var originalData = "Test data"u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        var encrypted = await Age.EncryptAsync(originalData, [recipient]);

        await Assert.ThrowsAsync<AgeDecryptionException>(
            () => Age.DecryptAsync(encrypted, Array.Empty<IIdentity>()));
    }

    [Fact]
    public async Task TryEncryptAsync_Tuple_ReturnsSuccessAndData()
    {
        var originalData = "Test data"u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        var (success, data) = await Age.TryEncryptAsync(originalData, [recipient]);

        Assert.True(success);
        Assert.NotNull(data);
    }

    [Fact]
    public async Task TryEncryptAsync_Tuple_ReturnsFalseOnFailure()
    {
        var originalData = "Test data"u8.ToArray();

        var (success, data) = await Age.TryEncryptAsync(originalData, Array.Empty<IRecipient>());

        Assert.False(success);
        Assert.Null(data);
    }

    [Fact]
    public async Task TryDecryptAsync_Tuple_ReturnsSuccessAndData()
    {
        var originalData = "Test data"u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        var encrypted = await Age.EncryptAsync(originalData, [recipient]);
        var (success, data) = await Age.TryDecryptAsync(encrypted, [identity]);

        Assert.True(success);
        Assert.Equal(originalData, data);
    }

    [Fact]
    public async Task TryDecryptAsync_Tuple_ReturnsFalseOnFailure()
    {
        var originalData = "Test data"u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var wrongIdentity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        var encrypted = await Age.EncryptAsync(originalData, [recipient]);
        var (success, data) = await Age.TryDecryptAsync(encrypted, [wrongIdentity]);

        Assert.False(success);
        Assert.Null(data);
    }

    [Fact]
    public void TryEncrypt_Sync_ReturnsTrueOnSuccess()
    {
        var originalData = "Test data"u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        var result = Age.TryEncrypt(originalData, [recipient], out var encrypted);

        Assert.True(result);
        Assert.NotNull(encrypted);
    }

    [Fact]
    public void TryDecrypt_Sync_ReturnsTrueOnSuccess()
    {
        var originalData = "Test data"u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        Age.TryEncrypt(originalData, [recipient], out var encrypted);
        var result = Age.TryDecrypt(encrypted!, [identity], out var decrypted);

        Assert.True(result);
        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    public async Task TryEncrypt_Stream_ReturnsTrueOnSuccess()
    {
        var originalData = "Test data"u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        using var input = new MemoryStream(originalData);
        using var output = new MemoryStream();
        var result = await Age.TryEncryptAsync(input, output, [recipient]);

        Assert.True(result);
    }

    [Fact]
    public async Task TryDecrypt_Stream_ReturnsTrueOnSuccess()
    {
        var originalData = "Test data"u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        using var input = new MemoryStream(originalData);
        using var encryptedStream = new MemoryStream();
        await Age.EncryptAsync(input, encryptedStream, [recipient]);

        encryptedStream.Position = 0;
        using var decryptedStream = new MemoryStream();
        var result = await Age.TryDecryptAsync(encryptedStream, decryptedStream, [identity]);

        Assert.True(result);
    }

    [Fact]
    public async Task Encrypt_LargeData_RoundtripsCorrectly()
    {
        var originalData = new byte[1024 * 100];
        RandomNumberGenerator.Fill(originalData);
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        var encrypted = await Age.EncryptAsync(originalData, [recipient]);
        var decrypted = await Age.DecryptAsync(encrypted, [identity]);

        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    public async Task Encrypt_NullInput_ThrowsArgumentNullException()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => Age.EncryptAsync(null!, new MemoryStream(), [recipient]));
    }

    [Fact]
    public async Task Decrypt_NullInput_ThrowsArgumentNullException()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => Age.DecryptAsync(null!, new MemoryStream(), [identity]));
    }

    [Fact]
    public async Task Encrypt_NullOutput_ThrowsArgumentNullException()
    {
        var originalData = "Test"u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => Age.EncryptAsync(new MemoryStream(originalData), null!, [recipient]));
    }

    [Fact]
    public async Task Decrypt_NullOutput_ThrowsArgumentNullException()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());
        var encrypted = await Age.EncryptAsync("test"u8.ToArray(), [recipient]);

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => Age.DecryptAsync(new MemoryStream(encrypted), null!, [identity]));
    }

    [Fact]
    public async Task Encrypt_SmallData_RoundtripsCorrectly()
    {
        var originalData = "A"u8.ToArray();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        var encrypted = await Age.EncryptAsync(originalData, [recipient]);
        var decrypted = await Age.DecryptAsync(encrypted, [identity]);

        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    public async Task Encrypt_EmptyData_RoundtripsCorrectly()
    {
        var originalData = Array.Empty<byte>();
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        var encrypted = await Age.EncryptAsync(originalData, [recipient]);
        var decrypted = await Age.DecryptAsync(encrypted, [identity]);

        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    public async Task Encrypt_WithArmor_ReturnsArmoredData()
    {
        var originalData = System.Text.Encoding.ASCII.GetBytes("Hello, World!");
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        using var input = new MemoryStream(originalData);
        using var encryptedStream = new MemoryStream();
        var options = new EncryptionOptions { Armor = true };
        await Age.EncryptAsync(input, encryptedStream, [recipient], options);

        var encrypted = encryptedStream.ToArray();
        Assert.True(AgeArmor.IsArmored(encrypted));
    }

    [Fact]
    public async Task Encrypt_Decrypt_WithArmor_RoundtripsCorrectly()
    {
        var originalData = System.Text.Encoding.ASCII.GetBytes("Hello, World! This is a test message.");
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        using var input = new MemoryStream(originalData);
        using var encryptedStream = new MemoryStream();
        var options = new EncryptionOptions { Armor = true };
        await Age.EncryptAsync(input, encryptedStream, [recipient], options);

        var encrypted = encryptedStream.ToArray();
        var decrypted = await Age.DecryptAsync(encrypted, [identity]);

        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    public async Task EncryptAsync_Stream_WithArmor_DecryptAsync_Stream_Roundtrip()
    {
        var originalData = System.Text.Encoding.ASCII.GetBytes("Stream test data for encryption and decryption");
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        using var input = new MemoryStream(originalData);
        using var encryptedStream = new MemoryStream();
        var options = new EncryptionOptions { Armor = true };
        await Age.EncryptAsync(input, encryptedStream, [recipient], options);

        encryptedStream.Position = 0;
        using var decryptedStream = new MemoryStream();
        await Age.DecryptAsync(encryptedStream, decryptedStream, [identity]);

        Assert.Equal(originalData, decryptedStream.ToArray());
    }

    [Fact]
    public async Task Decrypt_ArmoredFile_AutoDetectsAndDecrypts()
    {
        var originalData = System.Text.Encoding.ASCII.GetBytes("Test data for auto-detect");
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        using var input = new MemoryStream(originalData);
        using var armoredStream = new MemoryStream();
        var options = new EncryptionOptions { Armor = true };
        await Age.EncryptAsync(input, armoredStream, [recipient], options);

        var armored = armoredStream.ToArray();
        var decrypted = await Age.DecryptAsync(armored, [identity]);

        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    public async Task Decrypt_NonArmoredFile_WorksWithoutArmor()
    {
        var originalData = System.Text.Encoding.ASCII.GetBytes("Test data without armor");
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeParser.ParseRecipient(identity.ToRecipientString());

        using var input = new MemoryStream(originalData);
        using var encryptedStream = new MemoryStream();
        var options = new EncryptionOptions { Armor = false };
        await Age.EncryptAsync(input, encryptedStream, [recipient], options);

        var encrypted = encryptedStream.ToArray();
        var decrypted = await Age.DecryptAsync(encrypted, [identity]);

        Assert.Equal(originalData, decrypted);
    }
}
