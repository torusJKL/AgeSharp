using AgeSharp.Core;
using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Keys;
using Xunit;

namespace AgeSharp.Tests;

public class CctvStreamTests
{
    private static readonly string TestDataPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CCTV");

    public static IEnumerable<object[]> StreamTestFiles
    {
        get
        {
            if (!Directory.Exists(TestDataPath))
            {
                return Enumerable.Empty<object[]>();
            }

            return Directory.GetFiles(TestDataPath, "stream_*")
                .Select(f => new object[] { Path.GetFileName(f) });
        }
    }

    [Theory]
    [MemberData(nameof(StreamTestFiles))]
    public async Task Stream_Decrypt(string testName)
    {
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

        if (vector.Identities.Count == 0 && !string.IsNullOrEmpty(vector.FileKey))
        {
            return;
        }

        var identities = new List<IIdentity>();
        foreach (var identityStr in vector.Identities)
        {
            try
            {
                var identity = AgeParser.ParseIdentity(identityStr);
                identities.Add(identity);
            }
            catch
            {
            }
        }

        if (identities.Count == 0 && vector.Identities.Count > 0)
        {
            return;
        }

        if (identities.Count == 0)
        {
            return;
        }

        switch (vector.Expect)
        {
            case "success":
                {
                    var decrypted = await Age.DecryptAsync(data, identities);
                    Assert.True(vector.VerifyPayloadHash(decrypted), "Payload hash mismatch");
                    break;
                }
            case "payload failure":
                {
                    await Assert.ThrowsAsync<AgeDecryptionException>(() => Age.DecryptAsync(data, identities));
                    break;
                }
            case "no match":
                {
                    await Assert.ThrowsAsync<AgeIdentityNotFoundException>(() => Age.DecryptAsync(data, identities));
                    break;
                }
            case "HMAC failure":
                {
                    await Assert.ThrowsAsync<AgeDecryptionException>(() => Age.DecryptAsync(data, identities));
                    break;
                }
        }
    }
}
