namespace AgeSharp.Tests;

public static class FeatureDetector
{
    public static bool ArmorSupported => true;

    public static bool X25519Supported => true;

    public static bool ScryptSupported => true;

    public static bool HybridSupported => false;

    public static bool CompressionSupported => false;
}
