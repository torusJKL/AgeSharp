using AgeSharp.Core;
using AgeSharp.Core.Exceptions;
using Xunit;

namespace AgeSharp.Tests;

public class AgeArmorTests
{
    private const string ArmorHeader = "-----BEGIN AGE ENCRYPTED FILE-----";
    private const string ArmorFooter = "-----END AGE ENCRYPTED FILE-----";

    [Fact]
    public void IsArmored_WithArmorHeader_ReturnsTrue()
    {
        var data = System.Text.Encoding.ASCII.GetBytes($"{ArmorHeader}\nSGVsbG8gV29ybGQ=\n{ArmorFooter}\n");
        Assert.True(AgeArmor.IsArmored(data));
    }

    [Fact]
    public void IsArmored_WithoutArmorHeader_ReturnsFalse()
    {
        var data = System.Text.Encoding.ASCII.GetBytes("SGVsbG8gV29ybGQ=");
        Assert.False(AgeArmor.IsArmored(data));
    }

    [Fact]
    public void IsArmored_WithArmorString_ReturnsTrue()
    {
        var text = $"{ArmorHeader}\nSGVsbG8gV29ybGQ=\n{ArmorFooter}\n";
        Assert.True(AgeArmor.IsArmored(text));
    }

    [Fact]
    public void IsArmored_WithoutArmorString_ReturnsFalse()
    {
        var text = "SGVsbG8gV29ybGQ=";
        Assert.False(AgeArmor.IsArmored(text));
    }

    [Fact]
    public void IsArmored_EmptyData_ReturnsFalse()
    {
        Assert.False(AgeArmor.IsArmored(Array.Empty<byte>()));
    }

    [Fact]
    public void Encode_ValidData_ReturnsPEMFormattedString()
    {
        var data = System.Text.Encoding.ASCII.GetBytes("Hello World");
        var result = AgeArmor.Encode(data);

        Assert.StartsWith(ArmorHeader, result);
        Assert.EndsWith($"{ArmorFooter}\n", result);
    }

    [Fact]
    public void Encode_Roundtrip()
    {
        var original = System.Text.Encoding.ASCII.GetBytes("Test data for armor encoding");
        var encoded = AgeArmor.Encode(original);
        var decoded = AgeArmor.Decode(encoded);

        Assert.Equal(original, decoded);
    }

    [Fact]
    public void Decode_ValidPEM_ReturnsOriginalData()
    {
        var data = System.Text.Encoding.ASCII.GetBytes("Hello World");
        var armored = AgeArmor.Encode(data);
        var result = AgeArmor.Decode(armored);

        Assert.Equal(data, result);
    }

    [Fact]
    public void Decode_ByteArray_ReturnsOriginalData()
    {
        var data = System.Text.Encoding.ASCII.GetBytes("Hello World");
        var armored = AgeArmor.Encode(data);
        var armoredBytes = System.Text.Encoding.ASCII.GetBytes(armored);
        var result = AgeArmor.Decode(armoredBytes);

        Assert.Equal(data, result);
    }

    [Fact]
    public void Decode_MissingHeader_ThrowsException()
    {
        var invalid = "SGVsbG8gV29ybGQ=\n";
        Assert.Throws<AgeFormatException>(() => AgeArmor.Decode(invalid));
    }

    [Fact]
    public void Decode_MissingFooter_ThrowsException()
    {
        var invalid = $"{ArmorHeader}\nSGVsbG8gV29ybGQ=\n";
        Assert.Throws<AgeFormatException>(() => AgeArmor.Decode(invalid));
    }

    [Fact]
    public void Decode_EmptyBody_ThrowsException()
    {
        var invalid = $"{ArmorHeader}\n{ArmorFooter}\n";
        Assert.Throws<AgeFormatException>(() => AgeArmor.Decode(invalid));
    }

    [Fact]
    public void Decode_WithWhitespaceAround_Succeeds()
    {
        var data = System.Text.Encoding.ASCII.GetBytes("Test data");
        var armored = $"   {ArmorHeader}\n{Convert.ToBase64String(data)}\n{ArmorFooter}\n   ";
        var result = AgeArmor.Decode(armored);

        Assert.Equal(data, result);
    }

    [Fact]
    public void Encode_Null_ThrowsException()
    {
        Assert.Throws<ArgumentNullException>(() => AgeArmor.Encode(null!));
    }

    [Fact]
    public void Decode_String_Null_ThrowsException()
    {
        Assert.Throws<ArgumentNullException>(() => AgeArmor.Decode((string)null!));
    }

    [Fact]
    public void Decode_ByteArray_Null_ThrowsException()
    {
        Assert.Throws<ArgumentNullException>(() => AgeArmor.Decode((byte[])null!));
    }

    [Fact]
    public void Decode_FooterBeforeHeader_ThrowsException()
    {
        var invalid = $"{ArmorFooter}\n{ArmorHeader}\nSGVsbG8gV29ybGQ=\n";
        Assert.Throws<AgeFormatException>(() => AgeArmor.Decode(invalid));
    }

    [Fact]
    public void Encode_WrapsAt64Columns()
    {
        var data = new byte[100];
        new Random(42).NextBytes(data);
        var result = AgeArmor.Encode(data);

        var lines = result.Split('\n');
        foreach (var line in lines.Take(lines.Length - 2))
        {
            if (string.IsNullOrEmpty(line)) continue;
            Assert.True(line.Length <= 64, $"Line exceeds 64 columns: {line.Length} chars");
        }
    }

    [Fact]
    public void Decode_UnwrappedBase64_Succeeds()
    {
        var base64 = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 });
        var armored = $"{ArmorHeader}\n{base64}\n{ArmorFooter}\n";

        var result = AgeArmor.Decode(armored);

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, result);
    }

    [Fact]
    public void Decode_WrappedBase64_Succeeds()
    {
        var base64 = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 });
        var wrapped = $"{base64.Substring(0, Math.Min(64, base64.Length))}\n";
        if (base64.Length > 64)
        {
            wrapped += base64.Substring(64) + "\n";
        }
        var armored = $"{ArmorHeader}\n{wrapped}{ArmorFooter}\n";

        var result = AgeArmor.Decode(armored);

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, result);
    }
}
