namespace NativeSecrets;

/// <summary>
/// Defines a contract for cross-platform access to the native OS credential store.
/// </summary>
public interface INativeSecrets
{
    /// <summary>
    /// Stores or updates a secret in the native OS credential store.
    /// </summary>
    /// <param name="service">The service or application identifier associated with the secret.</param>
    /// <param name="account">The account or username associated with the secret.</param>
    /// <param name="secret">The secret value (e.g., password or token) to store.</param>
    void SetSecret(string service, string account, string secret);

    /// <summary>
    /// Retrieves a secret from the native OS credential store.
    /// </summary>
    /// <param name="service">The service or application identifier associated with the secret.</param>
    /// <param name="account">The account or username associated with the secret.</param>
    /// <returns>The stored secret value, or <see langword="null"/> if the secret was not found.</returns>
    string? GetSecret(string service, string account);

    /// <summary>
    /// Deletes a secret from the native OS credential store.
    /// </summary>
    /// <param name="service">The service or application identifier associated with the secret.</param>
    /// <param name="account">The account or username associated with the secret.</param>
    void DeleteSecret(string service, string account);

    /// <summary>
    /// Checks whether a secret exists in the native OS credential store.
    /// </summary>
    /// <param name="service">The service or application identifier associated with the secret.</param>
    /// <param name="account">The account or username associated with the secret.</param>
    /// <returns><see langword="true"/> if the secret exists; otherwise, <see langword="false"/>.</returns>
    bool SecretExists(string service, string account);

    /// <summary>
    /// Asynchronously stores or updates a secret in the native OS credential store.
    /// </summary>
    /// <param name="service">The service or application identifier associated with the secret.</param>
    /// <param name="account">The account or username associated with the secret.</param>
    /// <param name="secret">The secret value (e.g., password or token) to store.</param>
    /// <param name="ct">A cancellation token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task SetSecretAsync(string service, string account, string secret, CancellationToken ct = default);

    /// <summary>
    /// Asynchronously retrieves a secret from the native OS credential store.
    /// </summary>
    /// <param name="service">The service or application identifier associated with the secret.</param>
    /// <param name="account">The account or username associated with the secret.</param>
    /// <param name="ct">A cancellation token to cancel the operation.</param>
    /// <returns>A task that returns the stored secret value, or <see langword="null"/> if not found.</returns>
    Task<string?> GetSecretAsync(string service, string account, CancellationToken ct = default);

    /// <summary>
    /// Asynchronously deletes a secret from the native OS credential store.
    /// </summary>
    /// <param name="service">The service or application identifier associated with the secret.</param>
    /// <param name="account">The account or username associated with the secret.</param>
    /// <param name="ct">A cancellation token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task DeleteSecretAsync(string service, string account, CancellationToken ct = default);

    /// <summary>
    /// Asynchronously checks whether a secret exists in the native OS credential store.
    /// </summary>
    /// <param name="service">The service or application identifier associated with the secret.</param>
    /// <param name="account">The account or username associated with the secret.</param>
    /// <param name="ct">A cancellation token to cancel the operation.</param>
    /// <returns>A task that returns <see langword="true"/> if the secret exists; otherwise, <see langword="false"/>.</returns>
    Task<bool> SecretExistsAsync(string service, string account, CancellationToken ct = default);
}
