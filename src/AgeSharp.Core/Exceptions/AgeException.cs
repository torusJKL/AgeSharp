namespace AgeSharp.Core.Exceptions;

/// <summary>
/// Base exception type for Age-related errors.
/// </summary>
public class AgeException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AgeException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public AgeException(string message) : base(message) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="AgeException"/> class with a specified error message and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="inner">The exception that is the cause of the current exception.</param>
    public AgeException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Exception thrown when an invalid Age format is encountered.
/// </summary>
public class AgeFormatException : AgeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AgeFormatException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public AgeFormatException(string message) : base(message) { }
}

/// <summary>
/// Exception thrown when an invalid key is encountered.
/// </summary>
public class AgeKeyException : AgeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AgeKeyException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public AgeKeyException(string message) : base(message) { }
}
