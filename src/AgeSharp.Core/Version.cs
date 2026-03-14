namespace AgeSharp.Core;

/// <summary>
/// Provides version information for AgeSharp.
/// </summary>
public static class Version
{
    private const string version = "0.1.0";

    /// <summary>
    /// Gets the version string with build type postfix.
    /// </summary>
    /// <returns>Version with "d" for debug builds or "r" for release builds.</returns>
    public static string GetVersion()
    {
#if DEBUG
        return version + "d";
#else
        return version + "r";
#endif
    }
}
