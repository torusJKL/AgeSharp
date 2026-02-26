using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;
using Xunit;

namespace AgeSharp.Tests.Encoding;

public class Base64NoPaddingTests
{
    [Fact]
    public void Encode_EmptyArray_ReturnsEmptyString()
    {
        var result = Base64NoPadding.Encode(Array.Empty<byte>());
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void Encode_KnownInput_ReturnsExpectedOutput()
    {
        var data = new byte[] { 1, 2, 3, 4 };
        var result = Base64NoPadding.Encode(data);
        Assert.Equal("AQIDBA", result);
    }

    [Fact]
    public void Encode_SingleByte_ReturnsCorrectOutput()
    {
        var data = new byte[] { 1 };
        var result = Base64NoPadding.Encode(data);
        Assert.Equal("AQ", result);
    }

    [Fact]
    public void Encode_TwoBytes_ReturnsCorrectOutput()
    {
        var data = new byte[] { 1, 2 };
        var result = Base64NoPadding.Encode(data);
        Assert.Equal("AQI", result);
    }

    [Fact]
    public void Encode_NoPadding()
    {
        var data = new byte[] { 1, 2, 3, 4 };
        var result = Base64NoPadding.Encode(data);
        Assert.DoesNotContain("=", result);
    }

    [Fact]
    public void Decode_EmptyString_ReturnsEmptyArray()
    {
        var result = Base64NoPadding.Decode(string.Empty);
        Assert.Empty(result);
    }

    [Fact]
    public void Decode_KnownInput_ReturnsExpectedOutput()
    {
        var data = Base64NoPadding.Decode("AQIDBA");
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, data);
    }

    [Fact]
    public void Decode_Roundtrip()
    {
        var original = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var encoded = Base64NoPadding.Encode(original);
        var decoded = Base64NoPadding.Decode(encoded);
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void Decode_WithPadding_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => Base64NoPadding.Decode("AQIDBA=="));
    }

    [Fact]
    public void Decode_WithPaddingInMiddle_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => Base64NoPadding.Decode("AQID=BA"));
    }

    [Fact]
    public void Decode_InvalidCharacter_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => Base64NoPadding.Decode("AQIDB@"));
    }

    [Fact]
    public void Decode_InvalidLength_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => Base64NoPadding.Decode("A"));
    }

    [Fact]
    public void Encode_Null_ThrowsException()
    {
        Assert.Throws<ArgumentNullException>(() => Base64NoPadding.Encode(null!));
    }

    [Fact]
    public void Decode_Null_ThrowsException()
    {
        Assert.Throws<ArgumentNullException>(() => Base64NoPadding.Decode(null!));
    }
}
