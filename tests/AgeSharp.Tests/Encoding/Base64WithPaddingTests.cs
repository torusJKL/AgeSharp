using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;
using Xunit;

namespace AgeSharp.Tests.Encoding;

public class Base64WithPaddingTests
{
    [Fact]
    public void Encode_EmptyArray_ReturnsEmptyString()
    {
        var result = Base64WithPadding.Encode(Array.Empty<byte>());
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void Encode_KnownInput_ReturnsExpectedOutput()
    {
        var data = new byte[] { 1, 2, 3, 4 };
        var result = Base64WithPadding.Encode(data);
        Assert.Equal("AQIDBA==", result);
    }

    [Fact]
    public void Encode_SingleByte_ReturnsCorrectOutput()
    {
        var data = new byte[] { 1 };
        var result = Base64WithPadding.Encode(data);
        Assert.Equal("AQ==", result);
    }

    [Fact]
    public void Encode_TwoBytes_ReturnsCorrectOutput()
    {
        var data = new byte[] { 1, 2 };
        var result = Base64WithPadding.Encode(data);
        Assert.Equal("AQI=", result);
    }

    [Fact]
    public void Encode_WithPadding()
    {
        var data = new byte[] { 1, 2, 3, 4 };
        var result = Base64WithPadding.Encode(data);
        Assert.Contains("=", result);
    }

    [Fact]
    public void Decode_EmptyString_ReturnsEmptyArray()
    {
        var result = Base64WithPadding.Decode(string.Empty);
        Assert.Empty(result);
    }

    [Fact]
    public void Decode_KnownInput_ReturnsExpectedOutput()
    {
        var data = Base64WithPadding.Decode("AQIDBA==");
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, data);
    }

    [Fact]
    public void Decode_Roundtrip()
    {
        var original = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var encoded = Base64WithPadding.Encode(original);
        var decoded = Base64WithPadding.Decode(encoded);
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void Decode_WithPadding_Succeeds()
    {
        var result = Base64WithPadding.Decode("AQIDBA==");
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, result);
    }

    [Fact]
    public void Decode_NoPadding_Succeeds()
    {
        var result = Base64WithPadding.Decode("AQID");
        Assert.Equal(new byte[] { 1, 2, 3 }, result);
    }

    [Fact]
    public void Decode_InvalidCharacter_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => Base64WithPadding.Decode("AQIDB@"));
    }

    [Fact]
    public void Decode_InvalidLength_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => Base64WithPadding.Decode("A"));
    }

    [Fact]
    public void Encode_Null_ThrowsException()
    {
        Assert.Throws<ArgumentNullException>(() => Base64WithPadding.Encode(null!));
    }

    [Fact]
    public void Decode_Null_ThrowsException()
    {
        Assert.Throws<ArgumentNullException>(() => Base64WithPadding.Decode(null!));
    }
}
