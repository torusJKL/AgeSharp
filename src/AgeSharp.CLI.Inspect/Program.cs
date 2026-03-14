using AgeSharp.CommandLine;
using System.Text.Json;

using AgeSharp.Core;
using AgeSharp.Core.Exceptions;

namespace AgeSharp.Inspect;

class Program
{
    static async Task<int> Main(string[] args)
    {
        var parser = new CommandLineParser("age-inspect");

        parser.AddUsage("[--json] [FILE]");

        var jsonOption = parser.AddFlag<bool>(
            ["--json"],
            "Output as JSON");

        var versionOption = parser.AddFlag<bool>(
            ["--version"],
            "Print version information.");

        var fileArgument = parser.AddArgument<string?>(
            "FILE",
            "Path to the age encrypted file (default: stdin)",
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

        var json = result.GetValueForOption<bool>(jsonOption);
        var filePath = result.GetValueForArgument<string?>(fileArgument);

        return await InspectFile(json, filePath);
    }

    private static async Task<int> InspectFile(bool json, string? filePath)
    {
        try
        {
            byte[] data;

            if (string.IsNullOrEmpty(filePath) || filePath == "-")
            {
                if (!Console.IsInputRedirected)
                {
                    Console.Error.WriteLine("Error: No input provided (stdin is not redirected)");
                    return 1;
                }

                using var memStream = new MemoryStream();
                Console.OpenStandardInput().CopyTo(memStream);
                data = memStream.ToArray();

                if (data.Length == 0)
                {
                    Console.Error.WriteLine("Error: No input provided (stdin is empty)");
                    return 1;
                }
            }
            else
            {
                data = File.ReadAllBytes(filePath);
            }

            var info = AgeInspector.Inspect(data);

            if (json)
            {
                OutputJson(info);
            }
            else
            {
                OutputHumanReadable(filePath, info);
            }

            return 0;
        }
        catch (FileNotFoundException)
        {
            Console.Error.WriteLine($"Error: File not found: {filePath}");
            return 3;
        }
        catch (AgeFormatException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 4;
        }
        catch (ArgumentNullException)
        {
            Console.Error.WriteLine("Error: File path is required");
            return 1;
        }
    }

    private static void OutputHumanReadable(string? filePath, AgeFileInfo info)
    {
        var displayName = string.IsNullOrEmpty(filePath) || filePath == "-" ? "stdin" : Path.GetFileName(filePath);
        Console.WriteLine($"{displayName} is an age file, version \"{info.Version}\".");
        Console.WriteLine();

        if (info.IsArmor)
        {
            Console.WriteLine("This file is ASCII-armored.");
            Console.WriteLine();
        }

        Console.WriteLine("This file is encrypted to the following recipient types:");

        foreach (var stanzaType in info.StanzaTypes)
        {
            Console.WriteLine($"  - \"{stanzaType}\"");
        }
        Console.WriteLine();

        var pqText = info.PostQuantum == "yes" ? "DOES" : "does NOT";
        Console.WriteLine($"This file {pqText} use post-quantum encryption.");
        Console.WriteLine();
        Console.WriteLine("Size breakdown (assuming it decrypts successfully):");
        Console.WriteLine();
        Console.WriteLine($"    {"Header",-30}{info.HeaderSize,8} bytes");

        if (info.IsArmor)
        {
            Console.WriteLine($"    {"Armor overhead",-30}{info.ArmorSize,8} bytes");
        }

        Console.WriteLine($"    {"Encryption overhead",-30}{info.Overhead,8} bytes");
        Console.WriteLine($"    {"Payload",-30}{info.PayloadSize,8} bytes");
        Console.WriteLine($"                                -----------------");
        var total = info.HeaderSize + info.Overhead + info.PayloadSize;
        if (info.IsArmor)
        {
            total += info.ArmorSize;
        }
        Console.WriteLine($"    {"Total",-30}{total,8} bytes");
        Console.WriteLine();
        Console.WriteLine("Tip: for machine-readable output, use --json.");
    }

    private static void OutputJson(AgeFileInfo info)
    {
        var output = new
        {
            version = info.Version,
            postquantum = info.PostQuantum,
            armor = info.IsArmor,
            stanza_types = info.StanzaTypes,
            sizes = new
            {
                header = info.HeaderSize,
                armor = info.ArmorSize,
                overhead = info.Overhead,
                min_payload = info.PayloadSize,
                max_payload = info.PayloadSize,
                min_padding = 0,
                max_padding = 0
            }
        };

        var options = new JsonSerializerOptions { WriteIndented = true };
        Console.WriteLine(JsonSerializer.Serialize(output, options));
    }
}
