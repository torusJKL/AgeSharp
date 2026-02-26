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

/// <summary>
/// Exception thrown when encryption fails.
/// </summary>
public class AgeEncryptionException : AgeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AgeEncryptionException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public AgeEncryptionException(string message) : base(message) { }
}

/// <summary>
/// Exception thrown when decryption fails.
/// </summary>
public class AgeDecryptionException : AgeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AgeDecryptionException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public AgeDecryptionException(string message) : base(message) { }
}

/// <summary>
/// Exception thrown when an unsupported feature is encountered.
/// </summary>
public class AgeUnsupportedFeatureException : AgeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AgeUnsupportedFeatureException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public AgeUnsupportedFeatureException(string message) : base(message) { }
}

/// <summary>
/// Exception thrown when no matching identity is found during decryption.
/// </summary>
public class AgeIdentityNotFoundException : AgeDecryptionException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AgeIdentityNotFoundException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public AgeIdentityNotFoundException(string message) : base(message) { }
}
