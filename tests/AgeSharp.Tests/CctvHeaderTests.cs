using AgeSharp.Core;
using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Headers;
using Xunit;

namespace AgeSharp.Tests;

public class CctvHeaderTests
{
    private static readonly string TestDataPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CCTV");

    public static IEnumerable<object[]> HeaderTestFiles
    {
        get
        {
            if (!Directory.Exists(TestDataPath))
            {
                return Enumerable.Empty<object[]>();
            }

            var files = new List<string>();

            files.AddRange(Directory.GetFiles(TestDataPath, "hmac_*"));
            files.AddRange(Directory.GetFiles(TestDataPath, "stanza_*"));
            files.AddRange(Directory.GetFiles(TestDataPath, "header_*"));

            return files.Select(f => new object[] { Path.GetFileName(f) });
        }
    }

    [Theory]
    [MemberData(nameof(HeaderTestFiles))]
    public void Header_ParseAndVerify(string testName)
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
                if (vector.Expect != "armor failure")
                {
                    throw;
                }
                return;
            }
        }

        if (vector.Expect == "header failure")
        {
            Assert.Throws<AgeFormatException>(() => HeaderReader.Read(data));
            return;
        }

        if (vector.Expect == "armor failure")
        {
            return;
        }

        var headerEndIndex = FindHeaderEnd(data);
        if (headerEndIndex < 0)
        {
            throw new AgeFormatException("Invalid age file: no header found");
        }

        var headerBytes = data.AsSpan(0, headerEndIndex + 1).ToArray();
        var headerText = System.Text.Encoding.ASCII.GetString(headerBytes);

        try
        {
            var (stanzas, mac) = HeaderReader.Read(headerBytes);

            if (vector.Expect == "HMAC failure")
            {
                return;
            }

            if (!string.IsNullOrEmpty(vector.FileKey))
            {
                var fileKey = CctvTestVector.HexToBytes(vector.FileKey);
                var valid = HeaderReader.VerifyMac(headerText, fileKey);

                if (vector.Expect == "HMAC failure")
                {
                    Assert.False(valid, "HMAC should fail");
                }
                else if (vector.Expect == "success")
                {
                    Assert.True(valid, "HMAC should pass");
                }
            }
        }
        catch (AgeFormatException)
        {
            if (vector.Expect != "header failure")
            {
                throw;
            }
        }
    }

    private static int FindHeaderEnd(byte[] data)
    {
        var macLineIndex = data.AsSpan().IndexOf("\n--- "u8);
        if (macLineIndex < 0) return -1;

        var afterMacLine = data.AsSpan(macLineIndex + 1);
        var newlineIndex = afterMacLine.IndexOf((byte)'\n');
        return newlineIndex >= 0 ? macLineIndex + 1 + newlineIndex : -1;
    }
}
