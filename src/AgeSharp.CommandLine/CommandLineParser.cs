namespace AgeSharp.CommandLine;

/// <summary>
/// Specifies the number of arguments an option or argument can accept.
/// </summary>
public enum ArgumentArity
{
    /// <summary>
    /// No arguments allowed.
    /// </summary>
    Zero = 0,
    /// <summary>
    /// Zero or one argument.
    /// </summary>
    ZeroOrOne = 1,
    /// <summary>
    /// Exactly one argument.
    /// </summary>
    One = 1,
    /// <summary>
    /// Zero or more arguments.
    /// </summary>
    ZeroOrMore = 2,
    /// <summary>
    /// One or more arguments.
    /// </summary>
    OneOrMore = 3
}

/// <summary>
/// Base class for command-line options.
/// </summary>
public abstract class Option
{
    /// <summary>
    /// Gets the aliases for this option.
    /// </summary>
    public string[] Aliases { get; }
    /// <summary>
    /// Gets the description of this option.
    /// </summary>
    public string Description { get; }

    /// <summary>
    /// Initializes a new instance of the Option class.
    /// </summary>
    /// <param name="aliases">The aliases for this option.</param>
    /// <param name="description">The description of this option.</param>
    protected Option(string[] aliases, string description)
    {
        Aliases = aliases;
        Description = description;
    }

    /// <summary>
    /// Gets the type of value this option accepts.
    /// </summary>
    public abstract Type ValueType { get; }
    /// <summary>
    /// Gets the default value for this option.
    /// </summary>
    public abstract object? GetDefaultValue();
    /// <summary>
    /// Parses the option value from the argument list.
    /// </summary>
    /// <param name="args">The argument enumerator.</param>
    /// <returns>The parsed value.</returns>
    public abstract object? Parse(IEnumerator<string> args);
}

/// <summary>
/// A command-line option with a specific value type.
/// </summary>
/// <typeparam name="T">The type of value this option accepts.</typeparam>
public class Option<T> : Option
{
    private readonly T _defaultValue;

    /// <summary>
    /// Initializes a new instance of the Option class.
    /// </summary>
    /// <param name="aliases">The aliases for this option.</param>
    /// <param name="description">The description of this option.</param>
    /// <param name="defaultValue">The default value for this option.</param>
    /// <param name="arity">The argument arity.</param>
    public Option(string[] aliases, string description, T defaultValue, ArgumentArity arity)
        : base(aliases, description)
    {
        _defaultValue = defaultValue;
    }

    /// <summary>
    /// Gets the type of value this option accepts.
    /// </summary>
    public override Type ValueType => typeof(T);

    /// <summary>
    /// Gets the default value for this option.
    /// </summary>
    /// <returns>The default value.</returns>
    public override object? GetDefaultValue() => _defaultValue;

    /// <summary>
    /// Parses the option value from the argument list.
    /// </summary>
    /// <param name="args">The argument enumerator.</param>
    /// <returns>The parsed value.</returns>
    public override object? Parse(IEnumerator<string> args)
    {
        if (typeof(T) == typeof(bool))
        {
            return true;
        }

        if (typeof(T) == typeof(string) && args.MoveNext())
        {
            return args.Current;
        }

        if (typeof(T) == typeof(string[]) && args.MoveNext())
        {
            var current = args.Current;
            return current.StartsWith('-') ? Array.Empty<string>() : new[] { current };
        }

        return default;
    }

    /// <summary>
    /// Gets the value of this option.
    /// </summary>
    /// <returns>The option value.</returns>
    public T GetValue()
    {
        return _defaultValue;
    }
}

/// <summary>
/// Base class for positional command-line arguments.
/// </summary>
public class Argument
{
    /// <summary>
    /// Gets the name of this argument.
    /// </summary>
    public string Name { get; }
    /// <summary>
    /// Gets the description of this argument.
    /// </summary>
    public string Description { get; }
    /// <summary>
    /// Gets the argument arity.
    /// </summary>
    public ArgumentArity Arity { get; }

    /// <summary>
    /// Initializes a new instance of the Argument class.
    /// </summary>
    /// <param name="name">The name of this argument.</param>
    /// <param name="description">The description of this argument.</param>
    /// <param name="arity">The argument arity.</param>
    public Argument(string name, string description, ArgumentArity arity)
    {
        Name = name;
        Description = description;
        Arity = arity;
    }

    /// <summary>
    /// Gets the type of value this argument accepts.
    /// </summary>
    public Type ValueType => typeof(string);

    /// <summary>
    /// Gets the default value for this argument.
    /// </summary>
    /// <returns>The default value.</returns>
    public virtual object? GetDefaultValue() => null;

    /// <summary>
    /// Gets the value of this argument.
    /// </summary>
    /// <param name="value">The parsed value.</param>
    /// <returns>The argument value.</returns>
    public virtual object? GetValue(object? value) => value;
}

/// <summary>
/// A positional command-line argument with a specific value type.
/// </summary>
/// <typeparam name="T">The type of value this argument accepts.</typeparam>
public class Argument<T> : Argument
{
    private readonly Func<T>? _defaultValueFactory;

    /// <summary>
    /// Initializes a new instance of the Argument class.
    /// </summary>
    /// <param name="name">The name of this argument.</param>
    /// <param name="description">The description of this argument.</param>
    /// <param name="defaultValueFactory">The default value factory.</param>
    /// <param name="arity">The argument arity.</param>
    public Argument(string name, string description, Func<T>? defaultValueFactory, ArgumentArity arity)
        : base(name, description, arity)
    {
        _defaultValueFactory = defaultValueFactory;
    }

    /// <summary>
    /// Gets the default value for this argument.
    /// </summary>
    /// <returns>The default value.</returns>
    public override object? GetDefaultValue() => _defaultValueFactory is null ? default : _defaultValueFactory.Invoke();

    /// <summary>
    /// Gets the typed value of this argument.
    /// </summary>
    /// <returns>The argument value.</returns>
    public T? GetTypedValue()
    {
        return _defaultValueFactory is null ? default(T) : _defaultValueFactory.Invoke();
    }
}

/// <summary>
/// Represents a parse error.
/// </summary>
public class ParseError
{
    /// <summary>
    /// Gets the error message.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// Initializes a new instance of the ParseError class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public ParseError(string message)
    {
        Message = message;
    }
}

internal record ParsingState(
    string[] Args,
    int Index,
    List<ParseError> Errors,
    Dictionary<Option, object?> OptionValues,
    List<string> PositionalValues,
    bool SeenPositional)
{
    public ParsingState(string[] args)
        : this(args, 0, new List<ParseError>(), new Dictionary<Option, object?>(), new List<string>(), false)
    {
    }

    public string CurrentArg => Args[Index];

    public bool HasMoreArgs() => Index < Args.Length;

    public ParsingState Advance() => this with { Index = Index + 1 };

    public void CollectRemainingPositional()
    {
        for (int i = Index + 1; i < Args.Length; i++)
        {
            PositionalValues.Add(Args[i]);
        }
    }
}

internal readonly struct OptionParseResult
{
    public bool Success { get; }
    public Option? Option { get; }
    public int NextIndex { get; }
    public bool ConsumedValue { get; }

    private OptionParseResult(bool success, Option? option, int nextIndex, bool consumedValue)
    {
        Success = success;
        Option = option;
        NextIndex = nextIndex;
        ConsumedValue = consumedValue;
    }

    public static OptionParseResult Failure(int nextIndex)
        => new(false, null, nextIndex, false);

    public static OptionParseResult CreateSuccess(Option option, int nextIndex, bool consumedValue)
        => new(true, option, nextIndex, consumedValue);

    public void Deconstruct(out bool success, out Option? option, out int nextIndex, out bool consumedValue)
    {
        success = Success;
        option = Option;
        nextIndex = NextIndex;
        consumedValue = ConsumedValue;
    }
}

internal interface IArgumentHandler
{
    bool CanHandle(ParsingState state);
    ParsingState Handle(ParsingState state);
}

internal sealed class DelimiterHandler : IArgumentHandler
{
    public bool CanHandle(ParsingState state) => state.CurrentArg == "--";

    public ParsingState Handle(ParsingState state)
    {
        state.CollectRemainingPositional();
        return state with { SeenPositional = true, Index = state.Args.Length };
    }
}

internal sealed class HelpHandler : IArgumentHandler
{
    public bool CanHandle(ParsingState state) => state.CurrentArg == "--help" || state.CurrentArg == "-h";

    public ParsingState Handle(ParsingState state)
    {
        return (state with
        {
            SeenPositional = true,
            PositionalValues = state.PositionalValues.Append(state.CurrentArg).ToList()
        }).Advance();
    }
}

internal sealed class OptionHandler : IArgumentHandler
{
    private readonly CommandLineParser _parser;

    public OptionHandler(CommandLineParser parser) => _parser = parser;

    public bool CanHandle(ParsingState state) => state.CurrentArg.StartsWith('-') && state.CurrentArg != "--";

    public ParsingState Handle(ParsingState state)
    {
        var result = _parser.TryParseOption(state.Args, state.Index);

        if (!result.Success)
        {
            return HandleUnknownOption(state);
        }

        if (result.Option is not { } option)
        {
            return HandleUnknownOption(state);
        }

        var value = option.Parse(new PeekableEnumerator(state.Args, result.NextIndex));
        var newIndex = result.ConsumedValue ? result.NextIndex + 1 : result.NextIndex;

        var newOptionValues = new Dictionary<Option, object?>(state.OptionValues)
        {
            [option] = state.OptionValues.TryGetValue(option, out var existing)
                ? OptionValueExtensions.MergeOptionValue(existing, value)
                : value
        };

        return state with
        {
            OptionValues = newOptionValues,
            Index = newIndex
        };
    }

    private ParsingState HandleUnknownOption(ParsingState state)
    {
        var arg = state.CurrentArg;
        var errors = state.Errors;

        if (state.SeenPositional)
        {
            errors.Add(new ParseError($"Unexpected option '{arg}' after positional argument"));
            return state with { Index = state.Args.Length };
        }

        errors.Add(new ParseError($"Unknown option '{arg}'"));
        return state.Advance();
    }
}

internal sealed class PositionalHandler : IArgumentHandler
{
    public bool CanHandle(ParsingState state) => true;

    public ParsingState Handle(ParsingState state)
    {
        return (state with
        {
            SeenPositional = true,
            PositionalValues = state.PositionalValues.Append(state.CurrentArg).ToList()
        }).Advance();
    }
}

/// <summary>
/// Represents the result of parsing command-line arguments.
/// </summary>
public class ParseResult
{
    /// <summary>
    /// Gets the list of parse errors.
    /// </summary>
    public IReadOnlyList<ParseError> Errors { get; }
    private readonly Dictionary<Option, object?> _optionValues = new();
    private readonly Dictionary<Argument, object?> _argumentValues = new();

    internal ParseResult(List<ParseError> errors)
    {
        Errors = errors;
    }

    internal void SetValue(Option option, object? value)
    {
        _optionValues[option] = value;
    }

    internal void SetValue(Argument argument, object? value)
    {
        _argumentValues[argument] = value;
    }

    /// <summary>
    /// Gets the value for the specified option.
    /// </summary>
    /// <typeparam name="T">The type of the option value.</typeparam>
    /// <param name="option">The option.</param>
    /// <returns>The option value.</returns>
    public T? GetValueForOption<T>(Option<T> option)
    {
        if (_optionValues.TryGetValue(option, out var value))
        {
            if (value is T typed)
            {
                return typed;
            }
            if (typeof(T) == typeof(string[]) && value is List<string> list)
            {
                return (T)(object)list.ToArray();
            }
        }
        return option.GetValue();
    }

    /// <summary>
    /// Gets the value for the specified argument.
    /// </summary>
    /// <typeparam name="T">The type of the argument value.</typeparam>
    /// <param name="argument">The argument.</param>
    /// <returns>The argument value.</returns>
    public T? GetValueForArgument<T>(Argument<T> argument)
    {
        if (_argumentValues.TryGetValue(argument, out var value))
        {
            return (T?)argument.GetValue(value);
        }
        return argument.GetTypedValue();
    }

    internal object? GetRawOptionValue(Option option)
    {
        return _optionValues.GetValueOrDefault(option);
    }

    internal object? GetRawArgumentValue(Argument argument)
    {
        return _argumentValues.GetValueOrDefault(argument);
    }
}

/// <summary>
/// Command-line parser with options-first argument order.
/// </summary>
public class CommandLineParser
{
    private readonly string _description;
    private readonly List<Option> _options = new();
    private readonly Dictionary<string, Option> _optionLookup = new();
    private readonly List<Argument> _arguments = new();
    private readonly List<string> _usages = new();
    private readonly List<IArgumentHandler> _handlers;
    Func<object?[], Task>? _handler;

    /// <summary>
    /// Initializes a new instance of the CommandLineParser class.
    /// </summary>
    /// <param name="description">The description of the command.</param>
    public CommandLineParser(string description)
    {
        _description = description;
        _handlers = new List<IArgumentHandler>
        {
            new DelimiterHandler(),
            new HelpHandler(),
            new OptionHandler(this),
            new PositionalHandler()
        };
    }

    /// <summary>
    /// Adds a usage string for help display.
    /// </summary>
    /// <param name="usage">The usage string.</param>
    public void AddUsage(string usage)
    {
        _usages.Add(usage);
    }

    /// <summary>
    /// Adds a boolean flag option.
    /// </summary>
    /// <typeparam name="T">The type of the flag (always bool).</typeparam>
    /// <param name="aliases">The aliases for the option.</param>
    /// <param name="description">The description of the option.</param>
    /// <returns>The created option.</returns>
    public Option<T> AddFlag<T>(string[] aliases, string description) where T : struct
    {
        var option = new Option<T>(aliases, description, default(T), ArgumentArity.Zero);
        _options.Add(option);
        RegisterOptionAliases(option);
        return option;
    }

    /// <summary>
    /// Adds a single-value option.
    /// </summary>
    /// <param name="aliases">The aliases for the option.</param>
    /// <param name="description">The description of the option.</param>
    /// <returns>The created option.</returns>
    public Option<string?> AddOption(string[] aliases, string description)
    {
        var option = new Option<string?>(aliases, description, null, ArgumentArity.ZeroOrOne);
        _options.Add(option);
        RegisterOptionAliases(option);
        return option;
    }

    /// <summary>
    /// Adds a multi-value option.
    /// </summary>
    /// <param name="aliases">The aliases for the option.</param>
    /// <param name="description">The description of the option.</param>
    /// <returns>The created option.</returns>
    public Option<string[]> AddMultiValueOption(string[] aliases, string description)
    {
        var option = new Option<string[]>(aliases, description, Array.Empty<string>(), ArgumentArity.ZeroOrMore);
        _options.Add(option);
        RegisterOptionAliases(option);
        return option;
    }

    /// <summary>
    /// Adds a positional argument.
    /// </summary>
    /// <typeparam name="T">The type of the argument.</typeparam>
    /// <param name="name">The name of the argument.</param>
    /// <param name="description">The description of the argument.</param>
    /// <param name="defaultValueFactory">The default value factory.</param>
    /// <param name="arity">The argument arity.</param>
    /// <returns>The created argument.</returns>
    public Argument<T> AddArgument<T>(string name, string description, Func<T>? defaultValueFactory = null, ArgumentArity arity = ArgumentArity.ZeroOrOne)
    {
        var argument = new Argument<T>(name, description, defaultValueFactory, arity);
        _arguments.Add(argument);
        return argument;
    }

    /// <summary>
    /// Sets the handler to invoke when parsing is complete.
    /// </summary>
    /// <param name="handler">The handler delegate.</param>
    public void SetHandler(Delegate handler)
    {
        _handler = args =>
        {
            var result = handler.DynamicInvoke(args);
            return result is Task task ? task : throw new InvalidOperationException("Handler must return a Task");
        };
    }

    /// <summary>
    /// Parses the command-line arguments.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The parse result.</returns>
    public ParseResult Parse(string[] args)
    {
        var state = new ParsingState(args);

        while (state.HasMoreArgs())
        {
            var handler = _handlers.FirstOrDefault(h => h.CanHandle(state));
            if (handler != null)
            {
                state = handler.Handle(state);
            }
        }

        return BuildResult(state);
    }

    private ParseResult BuildResult(ParsingState state)
    {
        var result = new ParseResult(state.Errors);

        // Set values for all options (use provided value or default if not provided)
        foreach (var option in _options)
        {
            var value = state.OptionValues.GetValueOrDefault(option, option.GetDefaultValue());
            result.SetValue(option, value);
        }

        // Map positional arguments to their values
        for (int i = 0; i < _arguments.Count; ++i)
        {
            var value = i < state.PositionalValues.Count ? state.PositionalValues[i] : _arguments[i].GetDefaultValue();
            result.SetValue(_arguments[i], value);
        }

        return result;
    }

    private void RegisterOptionAliases(Option option)
    {
        foreach (var alias in option.Aliases)
        {
            _optionLookup[alias] = option;
        }
    }

    internal OptionParseResult TryParseOption(string[] args, int start)
    {
        var arg = args[start];

        if (arg.StartsWith("--"))
        {
            return TryParseLongOption(arg, start);
        }

        if (arg.StartsWith('-'))
        {
            return TryParseShortOption(arg, start);
        }

        return OptionParseResult.Failure(start + 1);
    }

    private OptionParseResult TryParseLongOption(string arg, int start)
    {
        var name = arg[2..];
        var nextIndex = start + 1;
        var hasEquals = name.Contains('=');

        if (!hasEquals)
        {
            var fullAlias = $"--{name}";
            if (_optionLookup.TryGetValue(fullAlias, out Option? option))
            {
                return OptionParseResult.CreateSuccess(option, nextIndex, option.ValueType != typeof(bool));
            }
            return OptionParseResult.Failure(nextIndex);
        }

        var parts = name.Split('=', 2);
        var alias = $"--{parts[0]}";

        if (_optionLookup.TryGetValue(alias, out Option? foundOption))
        {
            var newArgs = new[] { alias, parts[1] };
            foundOption.Parse(new PeekableEnumerator(newArgs, 0));
            return OptionParseResult.CreateSuccess(foundOption, nextIndex, true);
        }

        return OptionParseResult.Failure(nextIndex);
    }

    private OptionParseResult TryParseShortOption(string arg, int start)
    {
        var name = arg[1..];
        var alias = $"-{name}";
        var nextIndex = start + 1;

        if (_optionLookup.TryGetValue(alias, out var option))
        {
            var consumesValue = option.ValueType != typeof(bool);
            return OptionParseResult.CreateSuccess(option, nextIndex, consumesValue);
        }

        return OptionParseResult.Failure(nextIndex);
    }

    /// <summary>
    /// Parses and invokes the handler.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The exit code.</returns>
    public async Task<int> InvokeAsync(string[] args)
    {
        var result = Parse(args);

        if (result.Errors.Count > 0)
        {
            foreach (var error in result.Errors)
            {
                Console.Error.WriteLine(error.Message);
            }
            return 1;
        }

        if (args.Contains("--help") || args.Contains("-h"))
        {
            await PrintHelpAsync();
            return 0;
        }

        if (_handler is null)
        {
            return 0;
        }

        var handlerArgs = new List<object?>();

        foreach (var option in _options)
        {
            var value = result.GetRawOptionValue(option);
            handlerArgs.Add(value ?? option.GetDefaultValue());
        }

        foreach (var argument in _arguments)
        {
            var value = result.GetRawArgumentValue(argument);
            handlerArgs.Add(value);
        }

        try
        {
            await _handler(handlerArgs.ToArray());
            return 0;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Unexpected error: {ex.Message}");
            return 1;
        }
    }

    private async Task PrintHelpAsync()
    {
        Console.WriteLine("Usage:");
        if (_usages.Count > 0)
        {
            foreach (var usage in _usages)
            {
                Console.WriteLine($"    {_description} {usage}");
            }
        }
        else
        {
            Console.WriteLine($"    {_description}");
        }
        Console.WriteLine();
        Console.WriteLine("Options:");

        foreach (var option in _options)
        {
            var aliases = string.Join(", ", option.Aliases);
            Console.WriteLine($"  {aliases,-30} {option.Description}");
        }

        if (_arguments.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("Arguments:");

            foreach (var arg in _arguments)
            {
                Console.WriteLine($"  {arg.Name,-30} {arg.Description}");
            }
        }

        await Task.CompletedTask;
    }
}

internal static class OptionValueExtensions
{
    internal static object? MergeOptionValue(object? existing, object? value)
    {
        return (existing, value) switch
        {
            (List<string> list, string[] arr) => list.Also(_ => list.AddRange(arr)),
            (string[] oldArr, string[] newArr) => new List<string>(oldArr) { Capacity = oldArr.Length + newArr.Length }.Also(it => it.AddRange(newArr)),
            _ => value
        };
    }

    internal static T Also<T>(this T obj, Action<T> action) where T : class
    {
        action(obj);
        return obj;
    }
}

internal class PeekableEnumerator : IEnumerator<string>
{
    private readonly string[] _args;
    private readonly int _start;
    private int _index;
    private bool _moved;

    public PeekableEnumerator(string[] args, int start)
    {
        _args = args;
        _start = start;
        _index = start;
    }

    public string? Current { get; private set; }

    string IEnumerator<string>.Current => Current!;

    object? System.Collections.IEnumerator.Current => Current;

    public bool MoveNext()
    {
        if (_moved)
        {
            _index++;
        }
        _moved = true;

        if (_index < _args.Length)
        {
            Current = _args[_index];
            return true;
        }
        return false;
    }

    public void Reset()
    {
        _index = _start;
        _moved = false;
    }

    public void Dispose() { }
}
