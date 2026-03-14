namespace AgeSharp.Core;

/// <summary>
/// Information about an encrypted age file.
/// </summary>
public sealed class AgeFileInfo
{
    /// <summary>
    /// Gets the version string (e.g., "age-encryption.org/v1").
    /// </summary>
    public string Version { get; }

    /// <summary>
    /// Gets the list of stanza types (e.g., ["X25519"]).
    /// </summary>
    public List<string> StanzaTypes { get; }

    /// <summary>
    /// Gets the list of recipient keys from stanzas (ephemeral public keys).
    /// </summary>
    public List<string> RecipientKeys { get; }

    /// <summary>
    /// Gets whether the file is ASCII armored.
    /// </summary>
    public bool IsArmor { get; }

    /// <summary>
    /// Gets the size of the armor wrapper in bytes (0 if not armored).
    /// </summary>
    public long ArmorSize { get; }

    /// <summary>
    /// Gets the size of the header in bytes.
    /// </summary>
    public long HeaderSize { get; }

    /// <summary>
    /// Gets the encryption overhead in bytes.
    /// </summary>
    public long Overhead { get; }

    /// <summary>
    /// Gets the size of the payload in bytes.
    /// </summary>
    public long PayloadSize { get; }

    /// <summary>
    /// Gets whether the file uses post-quantum encryption ("yes", "no", or "unknown").
    /// </summary>
    public string PostQuantum { get; }

    /// <summary>
    /// Gets the header MAC (base64 encoded).
    /// </summary>
    public string? Mac { get; }

    internal AgeFileInfo(string version, List<string> stanzaTypes, List<string> recipientKeys, bool isArmor, long armorSize, long headerSize, long overhead, long payloadSize, string postQuantum, string? mac)
    {
        Version = version;
        StanzaTypes = stanzaTypes;
        RecipientKeys = recipientKeys;
        IsArmor = isArmor;
        ArmorSize = armorSize;
        HeaderSize = headerSize;
        Overhead = overhead;
        PayloadSize = payloadSize;
        PostQuantum = postQuantum;
        Mac = mac;
    }
}
