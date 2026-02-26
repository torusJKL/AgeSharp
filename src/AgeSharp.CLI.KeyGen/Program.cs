using System.CommandLine;

using AgeSharp.Core;
using AgeSharp.Core.Encoding;

namespace AgeSharp.KeyGen;

class Program
{
    private const string Version = "0.1.0";

    static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("Generate a new age key pair");

        var outputOption = new Option<string>(
            aliases: ["-o", "--output"],
            description: "Output file path (default: stdout)");
        rootCommand.AddOption(outputOption);

        var yOption = new Option<bool>(
            name: "-y",
            description: "Convert an identity file to a recipients file");
        rootCommand.AddOption(yOption);

        var inputArgument = new Argument<string?>(
            name: "INPUT",
            description: "Input file path (default: stdin)",
            getDefaultValue: () => null);
        rootCommand.AddArgument(inputArgument);

        rootCommand.SetHandler(async (outputPath, yMode, inputPath) =>
        {
            if (yMode)
            {
                await ConvertIdentityToRecipient(outputPath, inputPath);
            }
            else
            {
                await GenerateKey(outputPath);
            }
        }, outputOption, yOption, inputArgument);

        return await rootCommand.InvokeAsync(args);
    }

    private static async Task GenerateKey(string? outputPath)
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var identityString = identity.ToIdentityString();
        var recipientString = identity.ToRecipientString();
        var created = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:sszzz");

        var output = $"# created: {created}\n# public key: {recipientString}\n{identityString}";

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            Console.WriteLine(output);
        }
        else
        {
            await File.WriteAllTextAsync(outputPath, output + "\n");
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
            await File.WriteAllTextAsync(outputPath, recipientString + "\n");
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
