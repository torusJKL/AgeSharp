namespace AgeSharp.Core;

/// <summary>
/// Options for encrypting data using the Age encryption format.
/// </summary>
public sealed record EncryptionOptions
{
    /// <summary>
    /// Gets or sets whether to use ASCII armor (PEM encoding) for the output.
    /// </summary>
    public bool Armor { get; init; } = false;

    /// <summary>
    /// Gets or sets the chunk size for streaming encryption.
    /// </summary>
    public int ChunkSize { get; init; } = 64 * 1024;
}
