using System.Security.Cryptography;

using AgeSharp.Core;
using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Headers;
using AgeSharp.Core.Keys;
using NSec.Cryptography;
using Xunit;

namespace AgeSharp.Tests.Headers;

public class HeaderTests
{
    [Fact]
    public void X25519Stanza_Create_GeneratesValidStanza()
    {
        var fileKey = RandomNumberGenerator.GetBytes(16);
        var recipientPublicKey = RandomNumberGenerator.GetBytes(32);

        var stanza = X25519Stanza.Create(fileKey, recipientPublicKey);

        Assert.NotNull(stanza);
        Assert.Equal("X25519", stanza.Type);
        Assert.Equal(32, stanza.Body.Length);
        Assert.Single(stanza.Arguments);
    }

    [Fact]
    public void X25519Stanza_Unwrap_ReturnsOriginalFileKey()
    {
        var fileKey = RandomNumberGenerator.GetBytes(16);
        var privateKey = RandomNumberGenerator.GetBytes(32);

        using var key = Key.Import(KeyAgreementAlgorithm.X25519, privateKey, KeyBlobFormat.RawPrivateKey);
        var recipientPublicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        var stanza = X25519Stanza.Create(fileKey, recipientPublicKey);
        var unwrappedKey = stanza.Unwrap(privateKey);

        Assert.Equal(fileKey, unwrappedKey);
    }

    [Fact]
    public void HeaderWriter_Write_GeneratesValidHeader()
    {
        var fileKey = RandomNumberGenerator.GetBytes(16);
        var recipientPublicKey = RandomNumberGenerator.GetBytes(32);

        var stanza = X25519Stanza.Create(fileKey, recipientPublicKey);
        var header = HeaderWriter.Write([stanza], fileKey);

        Assert.NotNull(header);
        Assert.StartsWith("age-encryption.org/v1\n", header);
        Assert.Contains("-> X25519 ", header);
        Assert.Contains("\n--- ", header);
    }

    [Fact]
    public void HeaderReader_Read_ParsesValidHeader()
    {
        var fileKey = RandomNumberGenerator.GetBytes(16);
        var recipientPublicKey = RandomNumberGenerator.GetBytes(32);

        var stanza = X25519Stanza.Create(fileKey, recipientPublicKey);
        var header = HeaderWriter.Write([stanza], fileKey);

        var (stanzas, mac) = HeaderReader.Read(header);

        Assert.Single(stanzas);
        Assert.Equal("X25519", stanzas[0].Type);
        Assert.Single(stanzas[0].Arguments);
        Assert.Equal(32, stanzas[0].Body.Length);
        Assert.NotEmpty(mac);
    }

    [Fact]
    public void HeaderReader_VerifyMac_ValidHeader_ReturnsTrue()
    {
        var fileKey = RandomNumberGenerator.GetBytes(16);
        var recipientPublicKey = RandomNumberGenerator.GetBytes(32);

        var stanza = X25519Stanza.Create(fileKey, recipientPublicKey);
        var header = HeaderWriter.Write([stanza], fileKey);

        var (stanzas, _) = HeaderReader.Read(header);
        var result = HeaderReader.VerifyMac(header, fileKey);

        Assert.True(result);
    }

    [Fact]
    public void HeaderReader_VerifyMac_WrongKey_ReturnsFalse()
    {
        var fileKey = RandomNumberGenerator.GetBytes(16);
        var wrongKey = RandomNumberGenerator.GetBytes(16);
        var recipientPublicKey = RandomNumberGenerator.GetBytes(32);

        var stanza = X25519Stanza.Create(fileKey, recipientPublicKey);
        var header = HeaderWriter.Write([stanza], fileKey);

        var result = HeaderReader.VerifyMac(header, wrongKey);

        Assert.False(result);
    }

    [Fact]
    public void HeaderReader_InvalidVersion_ThrowsException()
    {
        var invalidHeader = "invalid-version\n--- " + new string('A', 43);

        Assert.Throws<AgeFormatException>(() => HeaderReader.Read(invalidHeader));
    }

    [Fact]
    public void HeaderReader_MissingMac_ThrowsException()
    {
        var header = "age-encryption.org/v1\n-> X25519 ABC\n";

        Assert.Throws<AgeFormatException>(() => HeaderReader.Read(header));
    }

    [Fact]
    public void X25519Stanza_Roundtrip_WithRealKeys()
    {
        var identityPrivateKey = AgeKeyGenerator.GenerateX25519Key();
        var recipient = AgeKeyGenerator.GetRecipientString(identityPrivateKey);

        var recipientBytes = AgeBech32.DecodeRecipient(recipient);

        var fileKey = RandomNumberGenerator.GetBytes(16);

        var stanza = X25519Stanza.Create(fileKey, recipientBytes);

        var privateKey = AgeBech32.DecodeIdentity(identityPrivateKey.ToIdentityString());
        var unwrappedKey = stanza.Unwrap(privateKey);

        Assert.Equal(fileKey, unwrappedKey);
    }

    [Fact]
    public void HeaderReader_WithMultipleStanzas_ParsesCorrectly()
    {
        var fileKey = RandomNumberGenerator.GetBytes(16);
        var recipient1 = RandomNumberGenerator.GetBytes(32);
        var recipient2 = RandomNumberGenerator.GetBytes(32);

        var stanza1 = X25519Stanza.Create(fileKey, recipient1);
        var stanza2 = X25519Stanza.Create(fileKey, recipient2);

        var header = HeaderWriter.Write([stanza1, stanza2], fileKey);

        var (stanzas, mac) = HeaderReader.Read(header);

        Assert.Equal(2, stanzas.Count);
        Assert.Equal("X25519", stanzas[0].Type);
        Assert.Equal("X25519", stanzas[1].Type);
        Assert.NotEmpty(mac);
    }

    [Fact]
    public void HeaderReader_WithWhitespaceLines_ParsesCorrectly()
    {
        var fileKey = RandomNumberGenerator.GetBytes(16);
        var recipientPublicKey = RandomNumberGenerator.GetBytes(32);

        var stanza = X25519Stanza.Create(fileKey, recipientPublicKey);
        var header = HeaderWriter.Write([stanza], fileKey);

        var headerWithWhitespace = "age-encryption.org/v1\n\n   \n" + header[22..];

        var (stanzas, mac) = HeaderReader.Read(headerWithWhitespace);

        Assert.Single(stanzas);
        Assert.Equal("X25519", stanzas[0].Type);
        Assert.NotEmpty(mac);
    }

    [Fact]
    public void HeaderReader_MacBeforeStanzas_ThrowsException()
    {
        var header = "age-encryption.org/v1\n--- " + new string('A', 43) + "\n-> X25519 ABC\nDEF";

        Assert.Throws<AgeFormatException>(() => HeaderReader.Read(header));
    }

    [Fact]
    public void HeaderReader_InvalidMacLength_ThrowsException()
    {
        var fileKey = RandomNumberGenerator.GetBytes(16);
        var recipientPublicKey = RandomNumberGenerator.GetBytes(32);

        var stanza = X25519Stanza.Create(fileKey, recipientPublicKey);
        var header = HeaderWriter.Write([stanza], fileKey);

        var invalidHeader = header[..^43] + "SHORT";

        Assert.Throws<AgeFormatException>(() => HeaderReader.Read(invalidHeader));
    }

    [Fact]
    public void HeaderReader_BodyLineTooLong_ThrowsException()
    {
        var header = "age-encryption.org/v1\n-> X25519 ABC\n" + new string('A', 65) + "\n--- " + new string('A', 43);

        Assert.Throws<AgeFormatException>(() => HeaderReader.Read(header));
    }

    [Fact]
    public void HeaderWriter_VerifyMac_IntegrationTest()
    {
        var fileKey = RandomNumberGenerator.GetBytes(16);
        var recipientPublicKey = RandomNumberGenerator.GetBytes(32);

        var stanza = X25519Stanza.Create(fileKey, recipientPublicKey);
        var header = HeaderWriter.Write([stanza], fileKey);

        var parsed = HeaderReader.Read(header);
        var verified = HeaderReader.VerifyMac(header, fileKey);

        Assert.Single(parsed.Stanzas);
        Assert.True(verified);
    }

    [Fact]
    public void HeaderReader_VerifyMac_TamperedHeader_ReturnsFalse()
    {
        var fileKey = RandomNumberGenerator.GetBytes(16);
        var recipientPublicKey = RandomNumberGenerator.GetBytes(32);

        var stanza = X25519Stanza.Create(fileKey, recipientPublicKey);
        var header = HeaderWriter.Write([stanza], fileKey);

        var tamperedHeader = header.Replace("X25519", "X25520");

        var verified = HeaderReader.VerifyMac(tamperedHeader, fileKey);

        Assert.False(verified);
    }
}
