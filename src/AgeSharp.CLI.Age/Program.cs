using AgeSharp.CommandLine;

using AgeSharp.Core;

namespace AgeSharp.CLI;

class Program
{
    static async Task<int> Main(string[] args)
    {
        var parser = new CommandLineParser("age");

        parser.AddUsage("[--encrypt] (-r RECIPIENT | -R PATH)... [--armor] [-o OUTPUT] [INPUT]");
        parser.AddUsage("--decrypt [-i PATH]... [-o OUTPUT] [INPUT]");

        var encryptOption = parser.AddFlag<bool>(
            ["-e", "--encrypt"],
            "Encrypt the input to the output. Default if omitted.");

        var decryptOption = parser.AddFlag<bool>(
            ["-d", "--decrypt"],
            "Decrypt the input to the output.");

        var outputOption = parser.AddOption(
            ["-o", "--output"],
            "Write the result to the file at path OUTPUT.");

        var recipientOption = parser.AddMultiValueOption(
            ["-r", "--recipient"],
            "Encrypt to the specified RECIPIENT. Can be repeated.");

        var recipientsFileOption = parser.AddMultiValueOption(
            ["-R", "--recipients-file"],
            "Encrypt to recipients listed at PATH. Can be repeated.");

        var identityOption = parser.AddMultiValueOption(
            ["-i", "--identity"],
            "Use the identity file at PATH. Can be repeated.");

        var armorOption = parser.AddFlag<bool>(
            ["-a", "--armor"],
            "Use ASCII armor (PEM encoding) for the output.");

        var versionOption = parser.AddFlag<bool>(
            ["--version"],
            "Print version information.");

        var inputArgument = parser.AddArgument<string?>(
            "input",
            "Input file to encrypt or decrypt. Defaults to stdin.",
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

        var encrypt = result.GetValueForOption(encryptOption);
        var decrypt = result.GetValueForOption(decryptOption);
        var output = result.GetValueForOption(outputOption);
        var recipients = result.GetValueForOption(recipientOption) ?? [];
        var recipientsFiles = result.GetValueForOption(recipientsFileOption) ?? [];
        var identities = result.GetValueForOption(identityOption) ?? [];
        var armor = result.GetValueForOption(armorOption);
        var input = result.GetValueForArgument(inputArgument);

        bool hasInput = encrypt || decrypt ||
                        false == string.IsNullOrEmpty(output) ||
                        recipients.Length > 0 || recipientsFiles.Length > 0 ||
                        identities.Length > 0 ||
                        false == string.IsNullOrEmpty(input);

        if (!hasInput)
        {
            return await parser.InvokeAsync(["--help"]);
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
            return 1;
        }

        return 0;
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
