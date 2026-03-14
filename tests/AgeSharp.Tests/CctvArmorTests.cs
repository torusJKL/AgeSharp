using AgeSharp.Core;
using AgeSharp.Core.Exceptions;
using Xunit;

namespace AgeSharp.Tests;

public class CctvArmorTests
{
    private static readonly string TestDataPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CCTV");

    public static IEnumerable<object[]> ArmorTestFiles => Directory.Exists(TestDataPath)
        ? Directory.GetFiles(TestDataPath, "armor_*")
            .Select(f => new object[] { Path.GetFileName(f) })
        : Enumerable.Empty<object[]>();

    [Theory]
    [MemberData(nameof(ArmorTestFiles))]
    public void Armor_ParseAndEncode(string testName)
    {
        var filePath = Path.Combine(TestDataPath, testName);
        if (!File.Exists(filePath))
        {
            return;
        }

        var content = File.ReadAllText(filePath);
        var vector = CctvTestVector.Parse(testName, content);

        if (vector.IsCompressed)
        {
            return;
        }

        var encryptedBytes = vector.EncryptedData;

        if (vector.Expect == "armor failure")
        {
            Assert.Throws<AgeFormatException>(() => AgeArmor.Decode(encryptedBytes));
            return;
        }

        var shouldBeArmored = vector.IsArmored || testName.StartsWith("armor_");

        if (!shouldBeArmored)
        {
            return;
        }

        try
        {
            var decoded = AgeArmor.Decode(encryptedBytes);
            var reEncoded = AgeArmor.Encode(decoded);
            var reDecoded = AgeArmor.Decode(reEncoded);

            Assert.Equal(decoded, reDecoded);
        }
        catch (AgeFormatException)
        {
            if (vector.Expect != "armor failure")
            {
                throw;
            }
        }
    }

    [Theory]
    [MemberData(nameof(ArmorTestFiles))]
    public void Armor_IsArmored(string testName)
    {
        var filePath = Path.Combine(TestDataPath, testName);
        if (!File.Exists(filePath))
        {
            return;
        }

        var content = File.ReadAllText(filePath);
        var vector = CctvTestVector.Parse(testName, content);

        var encryptedBytes = vector.EncryptedData;

        if (vector.IsCompressed)
        {
            return;
        }

        var shouldBeArmored = vector.IsArmored || testName.StartsWith("armor_");

        if (shouldBeArmored)
        {
            Assert.True(AgeArmor.IsArmored(encryptedBytes), $"Expected IsArmored to be true for {testName}");
        }
    }
}
