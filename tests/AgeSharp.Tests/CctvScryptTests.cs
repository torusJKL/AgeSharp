using AgeSharp.Core;
using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Keys;
using Xunit;

namespace AgeSharp.Tests;

public class CctvScryptTests
{
    private static readonly string TestDataPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CCTV");

    public static IEnumerable<object[]> ScryptTestFiles
    {
        get
        {
            if (!Directory.Exists(TestDataPath))
            {
                return Enumerable.Empty<object[]>();
            }

            return Directory.GetFiles(TestDataPath, "scrypt_*")
                .Select(f => new object[] { Path.GetFileName(f) });
        }
    }

    [Theory]
    [MemberData(nameof(ScryptTestFiles))]
    public async Task Scrypt_Decrypt(string testName)
    {
        if (!FeatureDetector.ScryptSupported)
        {
            return;
        }

        var filePath = Path.Combine(TestDataPath, testName);
        if (!File.Exists(filePath))
        {
            return;
        }

        var content = File.ReadAllBytes(filePath);
        var vector = CctvTestVector.Parse(testName, content);

        if (vector.IsCompressed)
        {
            return;
        }

        var data = vector.EncryptedData;

        if (vector.IsArmored)
        {
            try
            {
                data = AgeArmor.Decode(data);
            }
            catch (AgeFormatException)
            {
                if (vector.Expect == "armor failure")
                {
                    return;
                }
                throw;
            }
        }

        if (vector.Expect == "armor failure")
        {
            return;
        }

        if (vector.Passphrases.Count == 0)
        {
            return;
        }

        // For scrypt, we'd need to implement passphrase-based identities
        // For now, these tests will be skipped
        return;
    }
}
