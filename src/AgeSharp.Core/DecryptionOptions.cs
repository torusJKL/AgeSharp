namespace AgeSharp.Core;

/// <summary>
/// Options for decrypting data using the Age encryption format.
/// </summary>
public sealed record DecryptionOptions
{
    /// <summary>
    /// Gets or sets the chunk size for streaming decryption.
    /// </summary>
    public int ChunkSize { get; init; } = 64 * 1024;
}
