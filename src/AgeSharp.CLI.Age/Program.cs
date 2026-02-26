using System.CommandLine;

namespace AgeSharp.CLI;

class Program
{
    static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("AgeSharp - Age encryption tool");

        // TODO: Add encrypt/decrypt commands

        return await rootCommand.InvokeAsync(args);
    }
}
