using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Headers;

namespace AgeSharp.Core;

/// <summary>
/// Provides methods for inspecting age encrypted files.
/// </summary>
public static class AgeInspector
{
    private const string ArmorHeader = "-----BEGIN AGE ENCRYPTED FILE-----";
    private const string ArmorFooter = "-----END AGE ENCRYPTED FILE-----";
    private const int ChunkSize = 64 * 1024; // 64 KiB

    /// <summary>
    /// Inspects an age encrypted file and returns its metadata.
    /// </summary>
    /// <param name="filePath">Path to the encrypted file.</param>
    /// <returns>Information about the encrypted file.</returns>
    /// <exception cref="ArgumentNullException">Thrown when filePath is null.</exception>
    /// <exception cref="AgeFormatException">Thrown when the file is not a valid age file.</exception>
    public static AgeFileInfo Inspect(string filePath)
    {
        ArgumentNullException.ThrowIfNull(filePath);

        var data = File.ReadAllBytes(filePath);
        return Inspect(data);
    }

    /// <summary>
    /// Inspects an age encrypted stream and returns its metadata.
    /// </summary>
    /// <param name="stream">The encrypted stream.</param>
    /// <returns>Information about the encrypted file.</returns>
    /// <exception cref="ArgumentNullException">Thrown when stream is null.</exception>
    /// <exception cref="AgeFormatException">Thrown when the stream does not contain a valid age file.</exception>
    public static AgeFileInfo Inspect(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        using var memStream = new MemoryStream();
        stream.CopyTo(memStream);
        return Inspect(memStream.ToArray());
    }

    /// <summary>
    /// Inspects age encrypted data and returns its metadata.
    /// </summary>
    /// <param name="data">The encrypted data.</param>
    /// <returns>Information about the encrypted file.</returns>
    /// <exception cref="ArgumentNullException">Thrown when data is null.</exception>
    /// <exception cref="AgeFormatException">Thrown when the data is not a valid age file.</exception>
    public static AgeFileInfo Inspect(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        var (version, stanzaTypes, recipientKeys, isArmor, headerSize, armorSize, postQuantum, mac, decodedLength) = ParseHeader(data);
        var overhead = CalculateOverhead(decodedLength - headerSize);
        var payloadSize = decodedLength - headerSize - overhead;

        return new AgeFileInfo(version, stanzaTypes, recipientKeys, isArmor, armorSize, headerSize, overhead, payloadSize, postQuantum, mac);
    }

    private static (string Version, List<string> StanzaTypes, List<string> RecipientKeys, bool IsArmor, long HeaderSize, long ArmorSize, string PostQuantum, string? Mac, long DecodedLength) ParseHeader(byte[] data)
    {
        var isArmor = AgeArmor.IsArmored(data);
        var originalLength = data.Length;
        long armorSize = 0;

        if (isArmor)
        {
            var armorHeader = System.Text.Encoding.ASCII.GetString(data);
            var footerIndex = armorHeader.IndexOf(ArmorFooter, StringComparison.Ordinal);
            if (footerIndex < 0)
            {
                throw new AgeFormatException("Invalid armored file: missing footer");
            }

            var decodedData = AgeArmor.Decode(data);
            armorSize = originalLength - decodedData.Length;
            data = decodedData;
        }

        // Find header end
        var headerEndIndex = FindHeaderEnd(data);
        if (headerEndIndex < 0)
        {
            throw new AgeFormatException("Invalid age file: no header found");
        }

        var headerText = System.Text.Encoding.ASCII.GetString(data, 0, headerEndIndex + 1);
        var headerSize = headerEndIndex + 1;

        // Parse header
        var (stanzas, mac) = HeaderReader.Read(headerText);

        var stanzaTypes = new List<string>();
        var recipientKeys = new List<string>();
        foreach (var stanza in stanzas)
        {
            if (!stanzaTypes.Contains(stanza.Type))
            {
                stanzaTypes.Add(stanza.Type);
            }

            var recipientKey = stanza.TryGetRecipientKey();
            if (!string.IsNullOrEmpty(recipientKey))
            {
                recipientKeys.Add(recipientKey);
            }
        }

        // Extract version from first line
        var lines = headerText.Split('\n');
        if (lines.Length == 0 || string.IsNullOrEmpty(lines[0]))
        {
            throw new AgeFormatException("Invalid age file: missing version line");
        }
        var version = lines[0];

        // Determine post-quantum status
        var postQuantum = stanzaTypes.Any(t => t.StartsWith("mlkem", StringComparison.OrdinalIgnoreCase)) ? "yes" : "no";

        return (version, stanzaTypes, recipientKeys, isArmor, headerSize, armorSize, postQuantum, mac, data.Length);
    }

    private static int FindHeaderEnd(byte[] data)
    {
        var macLineIndex = data.AsSpan().IndexOf("\n--- "u8);
        if (macLineIndex < 0) return -1;

        var afterMacLine = data.AsSpan(macLineIndex + 1);
        var newlineIndex = afterMacLine.IndexOf((byte)'\n');
        return newlineIndex >= 0 ? macLineIndex + 1 + newlineIndex : -1;
    }

    private static long CalculateOverhead(long payloadSize)
    {
        // Reference: streamOverhead in age uses:
        // overhead = streamNonceSize (16) + numChunks * ChunkOverhead (16 per chunk)
        if (payloadSize <= 0) return 0;
        var numChunks = (payloadSize + ChunkSize - 1) / ChunkSize;
        if (numChunks < 1) numChunks = 1;
        return 16 + numChunks * 16;
    }
}
