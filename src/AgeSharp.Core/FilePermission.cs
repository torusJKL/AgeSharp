namespace AgeSharp.Core;

/// <summary>
/// Provides utilities for securing file permissions.
/// </summary>
public static class FilePermission
{
    /// <summary>
    /// Applies restrictive file permissions to a file (chmod 600 on Unix).
    /// </summary>
    /// <param name="path">The path to the file.</param>
    public static void SecureFile(string path)
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            try
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch
            {
            }
        }
        else if (OperatingSystem.IsWindows())
        {
            try
            {
                var fileInfo = new FileInfo(path);
                fileInfo.Attributes &= ~FileAttributes.ReadOnly;
            }
            catch
            {
            }
        }
    }
}
