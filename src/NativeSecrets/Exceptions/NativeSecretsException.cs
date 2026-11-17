namespace NativeSecrets.Exceptions;

/// <summary>
/// The exception that is thrown when an error occurs while accessing the native OS credential store.
/// </summary>
public class NativeSecretsException : Exception
{
    /// <summary>
    /// Gets the native OS keyring error code associated with this exception, if available.
    /// </summary>
    public int? ErrorCode { get; }
    /// <summary>
    /// Initializes a new instance of the <see cref="NativeSecretsException"/> class with a specified error message and optional native error code.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="errorCode">The optional native error code returned by the underlying keyring library.</param>
    public NativeSecretsException(string message, int? errorCode = null) : base(message) => ErrorCode = errorCode;

    /// <summary>
    /// Initializes a new instance of the <see cref="NativeSecretsException"/> class with a specified error message and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    /// <param name="inner">The exception that is the cause of the current exception.</param>
    public NativeSecretsException(string message, Exception inner) : base(message, inner) { }
}