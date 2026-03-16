using System.Diagnostics;

using Xunit;

namespace AgeSharp.CLI.Tests;

public class AgeCliTests
{
    private static readonly string RepoRoot = FindRepoRoot();
    private static readonly string CliProjectPath = Path.Combine(RepoRoot, "src", "AgeSharp.CLI.Age", "AgeSharp.CLI.csproj");
    private static readonly string KeyGenProjectPath = Path.Combine(RepoRoot, "src", "AgeSharp.CLI.KeyGen", "AgeSharp.KeyGen.csproj");

    private static string FindRepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir, "src", "AgeSharp.CLI.Age", "AgeSharp.CLI.csproj")))
            {
                return dir;
            }
            var parent = Directory.GetParent(dir);
            if (parent == null) break;
            dir = parent.FullName;
        }
        return Directory.GetCurrentDirectory();
    }

    [Fact]
    public async Task Encrypt_Decrypt_WithRecipient_ReturnsOriginalData()
    {
        await BuildProjectAsync(CliProjectPath);

        var originalData = "Hello, World!";
        var tempDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var keyFile = Path.Combine(tempDir, "key.txt");
            var plaintextFile = Path.Combine(tempDir, "plain.txt");
            var encryptedFile = Path.Combine(tempDir, "encrypted.age");
            var decryptedFile = Path.Combine(tempDir, "decrypted.txt");

            await File.WriteAllTextAsync(plaintextFile, originalData);

            var keyGenResult = await RunAsync("dotnet", $"run --project \"{KeyGenProjectPath}\" -o \"{keyFile}\"");
            Assert.Equal(0, keyGenResult.ExitCode);

            var publicKey = await GetPublicKeyFromFile(keyFile);

            var encryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -r \"{publicKey}\" -o \"{encryptedFile}\" \"{plaintextFile}\"");
            if (encryptResult.ExitCode != 0)
            {
                throw new Exception($"Encrypt failed. Stdout: {encryptResult.Stdout}, Stderr: {encryptResult.Stderr}");
            }
            Assert.True(File.Exists(encryptedFile));

            var decryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -d -i \"{keyFile}\" -o \"{decryptedFile}\" \"{encryptedFile}\"");
            Assert.Equal(0, decryptResult.ExitCode);

            var decryptedData = await File.ReadAllTextAsync(decryptedFile);
            Assert.Equal(originalData, decryptedData);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Encrypt_WithRecipientsFile_ReturnsEncryptedFile()
    {
        await BuildProjectAsync(CliProjectPath);

        var originalData = "Test data for recipients file";
        var tempDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var keyFile = Path.Combine(tempDir, "key.txt");
            var recipientsFile = Path.Combine(tempDir, "recipients.txt");
            var plaintextFile = Path.Combine(tempDir, "plain.txt");
            var encryptedFile = Path.Combine(tempDir, "encrypted.age");

            await File.WriteAllTextAsync(plaintextFile, originalData);

            var keyGenResult = await RunAsync("dotnet", $"run --project \"{KeyGenProjectPath}\" -o \"{keyFile}\"");
            Assert.Equal(0, keyGenResult.ExitCode);

            var publicKey = await GetPublicKeyFromFile(keyFile);
            await File.WriteAllTextAsync(recipientsFile, publicKey + "\n");

            var encryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -R \"{recipientsFile}\" -o \"{encryptedFile}\" \"{plaintextFile}\"");
            Assert.Equal(0, encryptResult.ExitCode);
            Assert.True(File.Exists(encryptedFile));
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Encrypt_MultipleRecipients_AllCanDecrypt()
    {
        await BuildProjectAsync(CliProjectPath);

        var originalData = "Multi-recipient test";
        var tempDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var keyFile1 = Path.Combine(tempDir, "key1.txt");
            var keyFile2 = Path.Combine(tempDir, "key2.txt");
            var plaintextFile = Path.Combine(tempDir, "plain.txt");
            var encryptedFile = Path.Combine(tempDir, "encrypted.age");
            var decryptedFile1 = Path.Combine(tempDir, "dec1.txt");
            var decryptedFile2 = Path.Combine(tempDir, "dec2.txt");

            await File.WriteAllTextAsync(plaintextFile, originalData);

            var kg1 = await RunAsync("dotnet", $"run --project \"{KeyGenProjectPath}\" -o \"{keyFile1}\"");
            var kg2 = await RunAsync("dotnet", $"run --project \"{KeyGenProjectPath}\" -o \"{keyFile2}\"");
            Assert.Equal(0, kg1.ExitCode);
            Assert.Equal(0, kg2.ExitCode);

            var publicKey1 = await GetPublicKeyFromFile(keyFile1);
            var publicKey2 = await GetPublicKeyFromFile(keyFile2);

            var encryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -r \"{publicKey1}\" -r \"{publicKey2}\" -o \"{encryptedFile}\" \"{plaintextFile}\"");
            Assert.Equal(0, encryptResult.ExitCode);

            var decryptResult1 = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -d -i \"{keyFile1}\" -o \"{decryptedFile1}\" \"{encryptedFile}\"");
            Assert.Equal(0, decryptResult1.ExitCode);

            var decryptResult2 = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -d -i \"{keyFile2}\" -o \"{decryptedFile2}\" \"{encryptedFile}\"");
            Assert.Equal(0, decryptResult2.ExitCode);

            var decryptedData1 = await File.ReadAllTextAsync(decryptedFile1);
            var decryptedData2 = await File.ReadAllTextAsync(decryptedFile2);

            Assert.Equal(originalData, decryptedData1);
            Assert.Equal(originalData, decryptedData2);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Encrypt_NoRecipient_ReturnsError()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var plaintextFile = Path.Combine(tempDir, "plain.txt");
            var encryptedFile = Path.Combine(tempDir, "encrypted.age");

            await File.WriteAllTextAsync(plaintextFile, "test");

            var result = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -o \"{encryptedFile}\" \"{plaintextFile}\"");
            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("at least one recipient", result.Stderr);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Decrypt_WrongIdentity_ReturnsError()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var keyFile1 = Path.Combine(tempDir, "key1.txt");
            var keyFile2 = Path.Combine(tempDir, "key2.txt");
            var plaintextFile = Path.Combine(tempDir, "plain.txt");
            var encryptedFile = Path.Combine(tempDir, "encrypted.age");

            await File.WriteAllTextAsync(plaintextFile, "test");

            await RunAsync("dotnet", $"run --project \"{KeyGenProjectPath}\" -o \"{keyFile1}\"");
            var publicKey = await GetPublicKeyFromFile(keyFile1);

            await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -r \"{publicKey}\" -o \"{encryptedFile}\" \"{plaintextFile}\"");

            await RunAsync("dotnet", $"run --project \"{KeyGenProjectPath}\" -o \"{keyFile2}\"");

            var result = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -d -i \"{keyFile2}\" -o \"{tempDir}/out.txt\" \"{encryptedFile}\"");
            Assert.NotEqual(0, result.ExitCode);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Encrypt_WithArmor_ReturnsArmoredFile()
    {
        await BuildProjectAsync(CliProjectPath);

        var originalData = "Hello, World with armor!";
        var tempDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var keyFile = Path.Combine(tempDir, "key.txt");
            var plaintextFile = Path.Combine(tempDir, "plain.txt");
            var encryptedFile = Path.Combine(tempDir, "encrypted.age");

            await File.WriteAllTextAsync(plaintextFile, originalData);

            var keyGenResult = await RunAsync("dotnet", $"run --project \"{KeyGenProjectPath}\" -o \"{keyFile}\"");
            Assert.Equal(0, keyGenResult.ExitCode);

            var publicKey = await GetPublicKeyFromFile(keyFile);

            var encryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -r \"{publicKey}\" -a -o \"{encryptedFile}\" \"{plaintextFile}\"");
            Assert.Equal(0, encryptResult.ExitCode);
            Assert.True(File.Exists(encryptedFile));

            var encryptedContent = await File.ReadAllTextAsync(encryptedFile);
            Assert.StartsWith("-----BEGIN AGE ENCRYPTED FILE-----", encryptedContent);
            Assert.EndsWith("-----END AGE ENCRYPTED FILE-----\n", encryptedContent);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Encrypt_WithArmor_Decrypt_ReturnsOriginalData()
    {
        await BuildProjectAsync(CliProjectPath);

        var originalData = "Test data for armor encryption";
        var tempDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var keyFile = Path.Combine(tempDir, "key.txt");
            var plaintextFile = Path.Combine(tempDir, "plain.txt");
            var encryptedFile = Path.Combine(tempDir, "encrypted.age");
            var decryptedFile = Path.Combine(tempDir, "decrypted.txt");

            await File.WriteAllTextAsync(plaintextFile, originalData);

            var keyGenResult = await RunAsync("dotnet", $"run --project \"{KeyGenProjectPath}\" -o \"{keyFile}\"");
            Assert.Equal(0, keyGenResult.ExitCode);

            var publicKey = await GetPublicKeyFromFile(keyFile);

            var encryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -r \"{publicKey}\" --armor -o \"{encryptedFile}\" \"{plaintextFile}\"");
            Assert.Equal(0, encryptResult.ExitCode);

            var decryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -d -i \"{keyFile}\" -o \"{decryptedFile}\" \"{encryptedFile}\"");
            Assert.Equal(0, decryptResult.ExitCode);

            var decryptedData = await File.ReadAllTextAsync(decryptedFile);
            Assert.Equal(originalData, decryptedData);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Decrypt_ArmoredFile_AutoDetectsAndDecrypts()
    {
        await BuildProjectAsync(CliProjectPath);

        var originalData = "Auto-detect armored file";
        var tempDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var keyFile = Path.Combine(tempDir, "key.txt");
            var plaintextFile = Path.Combine(tempDir, "plain.txt");
            var encryptedFile = Path.Combine(tempDir, "encrypted.age");
            var decryptedFile = Path.Combine(tempDir, "decrypted.txt");

            await File.WriteAllTextAsync(plaintextFile, originalData);

            var keyGenResult = await RunAsync("dotnet", $"run --project \"{KeyGenProjectPath}\" -o \"{keyFile}\"");
            Assert.Equal(0, keyGenResult.ExitCode);

            var publicKey = await GetPublicKeyFromFile(keyFile);

            var encryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -r \"{publicKey}\" -a -o \"{encryptedFile}\" \"{plaintextFile}\"");
            Assert.Equal(0, encryptResult.ExitCode);

            var decryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -d -i \"{keyFile}\" -o \"{decryptedFile}\" \"{encryptedFile}\"");
            Assert.Equal(0, decryptResult.ExitCode);

            var decryptedData = await File.ReadAllTextAsync(decryptedFile);
            Assert.Equal(originalData, decryptedData);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task Encrypt_WithoutArmor_ProducesBinaryFile()
    {
        await BuildProjectAsync(CliProjectPath);

        var tempDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var keyFile = Path.Combine(tempDir, "key.txt");
            var plaintextFile = Path.Combine(tempDir, "plain.txt");
            var encryptedFile = Path.Combine(tempDir, "encrypted.age");

            await File.WriteAllTextAsync(plaintextFile, "test");

            var keyGenResult = await RunAsync("dotnet", $"run --project \"{KeyGenProjectPath}\" -o \"{keyFile}\"");
            Assert.Equal(0, keyGenResult.ExitCode);

            var publicKey = await GetPublicKeyFromFile(keyFile);

            var encryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -r \"{publicKey}\" -o \"{encryptedFile}\" \"{plaintextFile}\"");
            Assert.Equal(0, encryptResult.ExitCode);

            var encryptedContent = await File.ReadAllTextAsync(encryptedFile);
            Assert.False(encryptedContent.StartsWith("-----BEGIN AGE ENCRYPTED FILE-----"));
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact(Skip = "Interactive passphrase input not supported in test environment")]
    public async Task Encrypt_WithPassphrase_ReturnsEncryptedFile()
    {
        await BuildProjectAsync(CliProjectPath);

        var tempDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var plaintextFile = Path.Combine(tempDir, "plain.txt");
            var encryptedFile = Path.Combine(tempDir, "encrypted.age");

            await File.WriteAllTextAsync(plaintextFile, "test passphrase data");

            var encryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -p -o \"{encryptedFile}\" \"{plaintextFile}\"");
            Assert.Equal(0, encryptResult.ExitCode);
            Assert.True(File.Exists(encryptedFile));
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact(Skip = "Interactive passphrase input not supported in test environment")]
    public async Task Encrypt_WithPassphrase_DecryptWithPassphrase_ReturnsOriginalData()
    {
        await BuildProjectAsync(CliProjectPath);

        var tempDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var plaintextFile = Path.Combine(tempDir, "plain.txt");
            var encryptedFile = Path.Combine(tempDir, "encrypted.age");
            var decryptedFile = Path.Combine(tempDir, "decrypted.txt");
            var passphraseFile = Path.Combine(tempDir, "passphrase.txt");

            var originalData = "Hello, passphrase world!";
            await File.WriteAllTextAsync(plaintextFile, originalData);

            var encryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -p -o \"{encryptedFile}\" \"{plaintextFile}\"");
            Assert.Equal(0, encryptResult.ExitCode);

            var encryptOutput = encryptResult.Stderr;
            var match = System.Text.RegularExpressions.Regex.Match(encryptOutput, @"Using the autogenerated passphrase ""([^""]+)""");
            Assert.True(match.Success, "Could not find autogenerated passphrase in output");
            var passphrase = match.Groups[1].Value;
            await File.WriteAllTextAsync(passphraseFile, passphrase);

            var decryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -d -i \"{passphraseFile}\" -o \"{decryptedFile}\" \"{encryptedFile}\"");
            Assert.Equal(0, decryptResult.ExitCode);

            var decryptedData = await File.ReadAllTextAsync(decryptedFile);
            Assert.Equal(originalData, decryptedData);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact(Skip = "Interactive passphrase input not supported in test environment")]
    public async Task Encrypt_PassphraseAndRecipient_ReturnsError()
    {
        await BuildProjectAsync(CliProjectPath);

        var tempDir = Path.Combine(Path.GetTempPath(), $"agesharp_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var keyFile = Path.Combine(tempDir, "key.txt");
            var plaintextFile = Path.Combine(tempDir, "plain.txt");
            var encryptedFile = Path.Combine(tempDir, "encrypted.age");

            await File.WriteAllTextAsync(plaintextFile, "test");

            var keyGenResult = await RunAsync("dotnet", $"run --project \"{KeyGenProjectPath}\" -o \"{keyFile}\"");
            Assert.Equal(0, keyGenResult.ExitCode);

            var publicKey = await GetPublicKeyFromFile(keyFile);

            var encryptResult = await RunAsync("dotnet", $"run --project \"{CliProjectPath}\" -- -p -r \"{publicKey}\" -o \"{encryptedFile}\" \"{plaintextFile}\"");
            Assert.NotEqual(0, encryptResult.ExitCode);
            Assert.Contains("cannot be used together", encryptResult.Stderr);
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    private static async Task<string> GetPublicKeyFromFile(string keyFile)
    {
        if (false == File.Exists(keyFile))
        {
            throw new InvalidOperationException($"Key file not found: {keyFile}");
        }

        var content = await File.ReadAllTextAsync(keyFile);
        var lines = content.Split('\n');
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("age1"))
            {
                return trimmed;
            }
            if (trimmed.StartsWith("# public key: "))
            {
                return trimmed.Substring("# public key: ".Length);
            }
        }
        throw new InvalidOperationException($"No public key found in key file. Content: {content}");
    }

    private static async Task BuildProjectAsync(string projectPath)
    {
        var result = await RunAsync("dotnet", $"build \"{projectPath}\"");
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException($"Build failed. Stdout: {result.Stdout}, Stderr: {result.Stderr}");
        }
    }

    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunAsync(string fileName, string arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = RepoRoot
        };

        using var process = Process.Start(startInfo);
        if (process == null)
        {
            throw new InvalidOperationException("Failed to start process");
        }

        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        return (process.ExitCode, stdout, stderr);
    }

    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunWithInputAsync(string fileName, string arguments, string input)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = RepoRoot
        };

        using var process = Process.Start(startInfo);
        if (process == null)
        {
            throw new InvalidOperationException("Failed to start process");
        }

        await process.StandardInput.WriteAsync(input);
        process.StandardInput.Close();

        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        return (process.ExitCode, stdout, stderr);
    }
}
