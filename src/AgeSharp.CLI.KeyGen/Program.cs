using AgeSharp.CommandLine;

using AgeSharp.Core;
using System.Globalization;

namespace AgeSharp.KeyGen;

class Program
{
    static async Task<int> Main(string[] args)
    {
        var parser = new CommandLineParser("age-keygen");

        parser.AddUsage("[-o OUTPUT]");
        parser.AddUsage("-y [INPUT]");

        var outputOption = parser.AddOption(
            ["-o", "--output"],
            "Output file path (default: stdout)");

        var yOption = parser.AddFlag<bool>(
            ["-y"],
            "Convert an identity file to a recipients file");

        var versionOption = parser.AddFlag<bool>(
            ["--version"],
            "Print version information.");

        var inputArgument = parser.AddArgument<string?>(
            "INPUT",
            "Input file path (default: stdin)",
            defaultValueFactory: () => null);

        var result = parser.Parse(args);

        if (args.Contains("--help") || args.Contains("-h"))
        {
            return await parser.InvokeAsync(["--help"]);
        }

        if (args.Contains("--version"))
        {
            Console.WriteLine(AgeSharp.Core.Version.GetVersion());
            return 0;
        }

        if (result.Errors.Count > 0)
        {
            foreach (var error in result.Errors)
            {
                Console.Error.WriteLine(error.Message);
            }
            return 1;
        }

        var outputPath = result.GetValueForOption(outputOption);
        var yMode = result.GetValueForOption(yOption);
        var inputPath = result.GetValueForArgument(inputArgument);

        if (yMode)
        {
            await ConvertIdentityToRecipient(outputPath, inputPath);
        }
        else
        {
            await GenerateKey(outputPath);
        }

        return 0;
    }

    private static async Task GenerateKey(string? outputPath)
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var identityString = identity.ToIdentityString();
        var recipientString = identity.ToRecipientString();
        var created = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:sszzz", CultureInfo.InvariantCulture);

        var output = $"# created: {created}\n# public key: {recipientString}\n{identityString}";

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            Console.WriteLine(output);
        }
        else
        {
            if (File.Exists(outputPath))
            {
                Console.Error.WriteLine($"Warning: overwriting existing file: {outputPath}");
            }
            await File.WriteAllTextAsync(outputPath, output + "\n");
            AgeSharp.Core.FilePermission.SecureFile(outputPath);
        }
    }

    private static async Task ConvertIdentityToRecipient(string? outputPath, string? inputPath)
    {
        string identityString;

        if (string.IsNullOrWhiteSpace(inputPath))
        {
            identityString = await Console.In.ReadToEndAsync();
        }
        else
        {
            identityString = await File.ReadAllTextAsync(inputPath);
        }

        identityString = ParseIdentityFromContent(identityString);

        var identity = AgeKeyGenerator.ParseIdentity(identityString);
        var recipientString = identity.ToRecipientString();

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            Console.WriteLine(recipientString);
        }
        else
        {
            if (File.Exists(outputPath))
            {
                Console.Error.WriteLine($"Warning: overwriting existing file: {outputPath}");
            }
            await File.WriteAllTextAsync(outputPath, recipientString + "\n");
            AgeSharp.Core.FilePermission.SecureFile(outputPath);
        }
    }

    private static string ParseIdentityFromContent(string content)
    {
        const string IdentityPrefix = "AGE-SECRET-KEY-";

        var lines = content.Split('\n');
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith(IdentityPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return trimmed;
            }
        }
        throw new ArgumentException("No identity found in input");
    }
}
