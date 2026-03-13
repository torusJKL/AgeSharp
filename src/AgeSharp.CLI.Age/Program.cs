using System.CommandLine;

using AgeSharp.Core;

namespace AgeSharp.CLI;

class Program
{
    private const string Version = "0.1.0";

    static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("AgeSharp - Age encryption tool");

        var encryptOption = new Option<bool>(
            aliases: ["-e", "--encrypt"],
            description: "Encrypt the input to the output. Default if omitted.");

        var decryptOption = new Option<bool>(
            aliases: ["-d", "--decrypt"],
            description: "Decrypt the input to the output.");

        var outputOption = new Option<string?>(
            aliases: ["-o", "--output"],
            description: "Write the result to the file at path OUTPUT.");

        var recipientOption = new Option<string[]>(
            aliases: ["-r", "--recipient"],
            description: "Encrypt to the specified RECIPIENT. Can be repeated.");

        var recipientsFileOption = new Option<string[]>(
            aliases: ["-R", "--recipients-file"],
            description: "Encrypt to recipients listed at PATH. Can be repeated.");

        var identityOption = new Option<string[]>(
            aliases: ["-i", "--identity"],
            description: "Use the identity file at PATH. Can be repeated.");

        var armorOption = new Option<bool>(
            aliases: ["-a", "--armor"],
            description: "Use ASCII armor (PEM encoding) for the output.");

        var inputArgument = new Argument<string?>(
            name: "input",
            description: "Input file to encrypt or decrypt. Defaults to stdin.")
        {
            Arity = ArgumentArity.ZeroOrOne
        };

        rootCommand.AddOption(encryptOption);
        rootCommand.AddOption(decryptOption);
        rootCommand.AddOption(outputOption);
        rootCommand.AddOption(recipientOption);
        rootCommand.AddOption(recipientsFileOption);
        rootCommand.AddOption(identityOption);
        rootCommand.AddOption(armorOption);
        rootCommand.AddArgument(inputArgument);

        rootCommand.SetHandler(async (encrypt, decrypt, output, recipients, recipientsFiles, identities, armor, input) =>
        {
            bool hasInput = encrypt || decrypt ||
                            false == string.IsNullOrEmpty(output) ||
                            recipients.Length > 0 || recipientsFiles.Length > 0 ||
                            identities.Length > 0 ||
                            false == string.IsNullOrEmpty(input);

            if (!hasInput)
            {
                await rootCommand.InvokeAsync(["--help"]);
                return;
            }

            if (decrypt)
            {
                await Decrypt(output, identities, input);
            }
            else if (recipients.Length > 0 || recipientsFiles.Length > 0)
            {
                await Encrypt(output, recipients, recipientsFiles, armor, input);
            }
            else
            {
                Console.Error.WriteLine("Error: at least one recipient is required");
                Environment.Exit(1);
            }
        }, encryptOption, decryptOption, outputOption, recipientOption, recipientsFileOption, identityOption, armorOption, inputArgument);

        return await rootCommand.InvokeAsync(args);
    }

    private static async Task Encrypt(string? output, string[] recipients, string[] recipientsFiles, bool armor, string? input)
    {
        var recipientList = new List<IRecipient>();

        foreach (var r in recipients)
        {
            recipientList.Add(AgeParser.ParseRecipient(r));
        }

        foreach (var file in recipientsFiles)
        {
            foreach (var r in AgeParser.ParseRecipientsFile(file))
            {
                recipientList.Add(r);
            }
        }

        if (recipientList.Count == 0)
        {
            Console.Error.WriteLine("Error: at least one recipient is required");
            Environment.Exit(1);
        }

        Stream inputStream;
        if (string.IsNullOrEmpty(input))
        {
            if (Console.IsInputRedirected)
            {
                var memStream = new MemoryStream();
                await Console.OpenStandardInput().CopyToAsync(memStream);
                memStream.Position = 0;
                inputStream = memStream;
            }
            else
            {
                Console.Error.WriteLine("Error: no input specified and stdin is not redirected");
                Environment.Exit(1);
                return;
            }
        }
        else
        {
            if (false == File.Exists(input))
            {
                Console.Error.WriteLine($"Error: input file not found: {input}");
                Environment.Exit(1);
                return;
            }
            inputStream = File.OpenRead(input);
        }

        using (inputStream)
        {
            Stream outputStream;

            if (string.IsNullOrEmpty(output))
            {
                if (Console.IsOutputRedirected)
                {
                    outputStream = Console.OpenStandardOutput();
                }
                else
                {
                    Console.Error.WriteLine("Error: refusing to write binary data to terminal. Use -o or redirect output.");
                    Environment.Exit(1);
                    return;
                }
            }
            else
            {
                outputStream = File.Create(output);
            }

            using (outputStream)
            {
                var options = new EncryptionOptions { Armor = armor };
                await Age.EncryptAsync(inputStream, outputStream, recipientList, options);
            }
        }
    }

    private static async Task Decrypt(string? output, string[] identities, string? input)
    {
        var identityList = new List<IIdentity>();

        foreach (var file in identities)
        {
            foreach (var identity in AgeParser.ParseIdentitiesFile(file))
            {
                identityList.Add(identity);
            }
        }

        if (identityList.Count == 0)
        {
            Console.Error.WriteLine("Error: at least one identity file is required for decryption");
            Environment.Exit(1);
        }

        Stream inputStream;
        if (string.IsNullOrEmpty(input))
        {
            if (Console.IsInputRedirected)
            {
                inputStream = Console.OpenStandardInput();
            }
            else
            {
                Console.Error.WriteLine("Error: no input specified and stdin is not redirected");
                Environment.Exit(1);
                return;
            }
        }
        else
        {
            if (false == File.Exists(input))
            {
                Console.Error.WriteLine($"Error: input file not found: {input}");
                Environment.Exit(1);
                return;
            }
            inputStream = File.OpenRead(input);
        }

        using (inputStream)
        {
            Stream outputStream;

            if (string.IsNullOrEmpty(output))
            {
                outputStream = Console.OpenStandardOutput();
            }
            else
            {
                outputStream = File.Create(output);
            }

            using (outputStream)
            {
                try
                {
                    await Age.DecryptAsync(inputStream, outputStream, identityList);
                }
                catch (Core.Exceptions.AgeDecryptionException ex)
                {
                    Console.Error.WriteLine($"Error: {ex.Message}");
                    Environment.Exit(1);
                }
            }
        }
    }
}
