namespace NativeSecrets.Exceptions;

/// <summary>
/// The exception that is thrown when the user denies access to the OS keyring or cancels the authentication prompt.
/// </summary>
public sealed class SecretAccessDeniedException : NativeSecretsException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SecretAccessDeniedException"/> class.
    /// </summary>
    public SecretAccessDeniedException()
        : base("User denied access or cancelled the OS prompt.", 3)
    {
    }
}