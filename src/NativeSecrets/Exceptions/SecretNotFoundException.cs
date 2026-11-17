namespace NativeSecrets.Exceptions;

/// <summary>
/// The exception that is thrown when a requested secret does not exist in the native OS credential store.
/// </summary>
public class SecretNotFoundException : NativeSecretsException
{
    /// <summary>
    /// Gets the service or application identifier associated with the missing secret.
    /// </summary>
    public string Service { get; }

    /// <summary>
    /// Gets the account or username associated with the missing secret.
    /// </summary>
    public string Account { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretNotFoundException"/> class for the specified service and account.
    /// </summary>
    /// <param name="service">The service or application identifier.</param>
    /// <param name="account">The account or username.</param>
    public SecretNotFoundException(string service, string account)
        : base($"Secret not found for '{service}/{account}'.", 2)
    {
        Service = service;
        Account = account;
    }
}