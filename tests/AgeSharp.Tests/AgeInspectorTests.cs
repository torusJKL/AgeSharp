using AgeSharp.Core;
using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Keys;
using Xunit;

namespace AgeSharp.Tests;

public class AgeInspectorTests
{
    [Fact]
    public void Inspect_BinaryFile_ReturnsVersionAndRecipients()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = identity.ToRecipientString();
        var testData = "Hello, World!"u8.ToArray();

        var encrypted = Age.EncryptAsync(testData, [AgeParser.ParseRecipient(recipient)]).GetAwaiter().GetResult();

        var info = AgeInspector.Inspect(encrypted);

        Assert.Equal("age-encryption.org/v1", info.Version);
        Assert.Single(info.StanzaTypes);
        Assert.Equal("X25519", info.StanzaTypes[0]);
        Assert.Single(info.RecipientKeys);
        Assert.StartsWith("age1", info.RecipientKeys[0]);
        Assert.False(info.IsArmor);
        Assert.Equal(0, info.ArmorSize);
        Assert.True(info.HeaderSize > 0);
        Assert.True(info.Overhead > 0);
        Assert.True(info.PayloadSize > 0);
        Assert.Equal("no", info.PostQuantum);
    }

    [Fact]
    public void Inspect_ArmoredFile_ReturnsVersionRecipientsAndIsArmor()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipient = identity.ToRecipientString();
        var testData = "Hello, World!"u8.ToArray();

        using var input = new MemoryStream(testData);
        using var encryptedStream = new MemoryStream();
        var options = new EncryptionOptions { Armor = true };
        Age.EncryptAsync(input, encryptedStream, [AgeParser.ParseRecipient(recipient)], options).GetAwaiter().GetResult();
        var encrypted = encryptedStream.ToArray();

        var info = AgeInspector.Inspect(encrypted);

        Assert.Equal("age-encryption.org/v1", info.Version);
        Assert.Single(info.StanzaTypes);
        Assert.Equal("X25519", info.StanzaTypes[0]);
        Assert.True(info.IsArmor);
        Assert.True(info.ArmorSize > 0);
    }

    [Fact]
    public void Inspect_MultipleRecipients_ReturnsAllRecipients()
    {
        var identity1 = AgeKeyGenerator.GenerateX25519Key();
        var identity2 = AgeKeyGenerator.GenerateX25519Key();
        var testData = "Hello, World!"u8.ToArray();

        var encrypted = Age.EncryptAsync(testData, 
            [AgeParser.ParseRecipient(identity1.ToRecipientString()), AgeParser.ParseRecipient(identity2.ToRecipientString())])
            .GetAwaiter().GetResult();

        var info = AgeInspector.Inspect(encrypted);

        // All stanzas are X25519 type
        Assert.Single(info.StanzaTypes);
        Assert.Equal("X25519", info.StanzaTypes[0]);
        // But there are 2 recipient keys (one per recipient)
        Assert.Equal(2, info.RecipientKeys.Count);
        Assert.All(info.RecipientKeys, r => Assert.StartsWith("age1", r));
    }

    [Fact]
    public void Inspect_InvalidData_ThrowsAgeFormatException()
    {
        var invalidData = "not a valid age file"u8.ToArray();

        Assert.Throws<AgeFormatException>(() => AgeInspector.Inspect(invalidData));
    }

    [Fact]
    public void Inspect_NullData_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => AgeInspector.Inspect((byte[])null!));
    }

    [Fact]
    public void Inspect_NullPath_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => AgeInspector.Inspect((string)null!));
    }

    [Fact]
    public void Inspect_EmptyData_ThrowsAgeFormatException()
    {
        var emptyData = Array.Empty<byte>();

        Assert.Throws<AgeFormatException>(() => AgeInspector.Inspect(emptyData));
    }

    [Fact]
    public void Inspect_SizeProperties_AreCalculatedCorrectly()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var testData = "Hello"u8.ToArray();

        var encrypted = Age.EncryptAsync(testData, [AgeParser.ParseRecipient(identity.ToRecipientString())]).GetAwaiter().GetResult();
        var info = AgeInspector.Inspect(encrypted);

        // Verify all sizes are positive
        Assert.True(info.HeaderSize > 0);
        Assert.True(info.Overhead > 0);
        Assert.True(info.PayloadSize > 0);
        // Total file size = header + overhead + payload (encrypted)
        Assert.Equal(encrypted.Length, info.HeaderSize + info.Overhead + info.PayloadSize);
    }
}
