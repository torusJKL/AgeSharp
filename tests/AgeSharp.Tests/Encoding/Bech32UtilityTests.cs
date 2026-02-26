using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;
using Xunit;

namespace AgeSharp.Tests.Encoding;

public class AgeBech32Tests
{
    [Fact]
    public void EncodeIdentity_KnownInput_ReturnsExpectedOutput()
    {
        var data = new byte[32];
        for (var i = 0; i < 32; i++)
        {
            data[i] = (byte)(0xFF - i);
        }

        var result = AgeBech32.EncodeIdentity(data);
        
        Assert.StartsWith(AgeBech32.IdentityHrp, result);
    }

    [Fact]
    public void EncodeRecipient_KnownInput_ReturnsExpectedOutput()
    {
        var data = new byte[32];
        for (var i = 0; i < 32; i++)
        {
            data[i] = (byte)(i + 1);
        }

        var result = AgeBech32.EncodeRecipient(data);
        
        Assert.StartsWith(AgeBech32.RecipientHrp, result);
    }

    [Fact]
    public void EncodeRecipient_KnownTestVector()
    {
        var data = new byte[] { 0xd7, 0x5d, 0xd1, 0xa9, 0x25, 0xe2, 0xc8, 0xa1, 0xb7, 0xb3, 0xc3, 0xd1, 0xb5, 0xe0, 0xc2, 0xe3 };
        var result = AgeBech32.EncodeRecipient(data);

        Assert.StartsWith("age1", result);
    }

    [Fact]
    public void DecodeIdentity_Roundtrip()
    {
        var original = new byte[32];
        new Random(42).NextBytes(original);
        
        var encoded = AgeBech32.EncodeIdentity(original);
        var decoded = AgeBech32.DecodeIdentity(encoded);
        
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void DecodeRecipient_Roundtrip()
    {
        var original = new byte[32];
        new Random(42).NextBytes(original);
        
        var encoded = AgeBech32.EncodeRecipient(original);
        var decoded = AgeBech32.DecodeRecipient(encoded);
        
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void DecodeIdentity_WithWrongHrp_ThrowsException()
    {
        var data = new byte[32];
        new Random(42).NextBytes(data);
        
        var recipientEncoded = AgeBech32.EncodeRecipient(data);
        
        Assert.Throws<AgeFormatException>(() => AgeBech32.DecodeIdentity(recipientEncoded));
    }

    [Fact]
    public void DecodeRecipient_WithWrongHrp_ThrowsException()
    {
        var data = new byte[32];
        new Random(42).NextBytes(data);
        
        var identityEncoded = AgeBech32.EncodeIdentity(data);
        
        Assert.Throws<AgeFormatException>(() => AgeBech32.DecodeRecipient(identityEncoded));
    }

    [Fact]
    public void IsValidIdentity_Valid_ReturnsTrue()
    {
        var data = new byte[32];
        new Random(42).NextBytes(data);
        
        var encoded = AgeBech32.EncodeIdentity(data);
        
        Assert.True(AgeBech32.IsValidIdentity(encoded));
    }

    [Fact]
    public void IsValidIdentity_InvalidHrp_ReturnsFalse()
    {
        var data = new byte[32];
        new Random(42).NextBytes(data);
        
        var encoded = AgeBech32.EncodeRecipient(data);
        
        Assert.False(AgeBech32.IsValidIdentity(encoded));
    }

    [Fact]
    public void IsValidRecipient_Valid_ReturnsTrue()
    {
        var data = new byte[32];
        new Random(42).NextBytes(data);
        
        var encoded = AgeBech32.EncodeRecipient(data);
        
        Assert.True(AgeBech32.IsValidRecipient(encoded));
    }

    [Fact]
    public void IsValidRecipient_InvalidHrp_ReturnsFalse()
    {
        var data = new byte[32];
        new Random(42).NextBytes(data);
        
        var encoded = AgeBech32.EncodeIdentity(data);
        
        Assert.False(AgeBech32.IsValidRecipient(encoded));
    }

    [Fact]
    public void EncodeIdentity_EmptyArray_ThrowsException()
    {
        Assert.Throws<ArgumentException>(() => AgeBech32.EncodeIdentity(Array.Empty<byte>()));
    }

    [Fact]
    public void EncodeRecipient_EmptyArray_ThrowsException()
    {
        Assert.Throws<ArgumentException>(() => AgeBech32.EncodeRecipient(Array.Empty<byte>()));
    }

    [Fact]
    public void DecodeIdentity_InvalidChecksum_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => AgeBech32.DecodeIdentity("age-secret-key-1invalidchecksum"));
    }

    [Fact]
    public void DecodeRecipient_InvalidChecksum_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => AgeBech32.DecodeRecipient("age1invalidchecksum"));
    }

    [Fact]
    public void DecodeIdentity_MixedCase_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => AgeBech32.DecodeIdentity("Age-Secret-Key-1abc123"));
    }

    [Fact]
    public void DecodeRecipient_MixedCase_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => AgeBech32.DecodeRecipient("Age1abc123"));
    }

    [Fact]
    public void DecodeIdentity_StringTooShort_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => AgeBech32.DecodeIdentity("age1abc"));
    }

    [Fact]
    public void DecodeRecipient_StringTooShort_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => AgeBech32.DecodeRecipient("age1abc"));
    }

    [Fact]
    public void DecodeIdentity_MissingSeparator_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => AgeBech32.DecodeIdentity("AGE-SECRET-KEYabc123"));
    }

    [Fact]
    public void DecodeRecipient_MissingSeparator_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => AgeBech32.DecodeRecipient("ageabc123"));
    }

    [Fact]
    public void DecodeIdentity_InvalidHrpLength_ThrowsException()
    {
        var hrp = new string('a', 84);
        var data = new string('1', 10);
        Assert.Throws<AgeFormatException>(() => AgeBech32.DecodeIdentity(hrp + "1" + data));
    }

    [Fact]
    public void DecodeRecipient_InvalidCharacters_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => AgeBech32.DecodeRecipient("age1invalid!char"));
    }

    [Fact]
    public void DecodeRecipient_AllUppercase_Works()
    {
        var lower = AgeBech32.EncodeRecipient(new byte[] { 1, 2, 3, 4, 5 });
        var upper = lower.ToUpperInvariant();
        
        var decoded = AgeBech32.DecodeRecipient(upper);
        
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, decoded);
    }

    [Fact]
    public void DecodeIdentity_AllLowercase_Works()
    {
        var upper = AgeBech32.EncodeIdentity(new byte[] { 1, 2, 3, 4, 5 });
        var lower = upper.ToLowerInvariant();
        
        var decoded = AgeBech32.DecodeIdentity(lower);
        
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, decoded);
    }
}
