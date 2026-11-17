namespace NativeSecrets;

/// <summary>
/// Provides a base implementation of <see cref="INativeSecrets"/> for cross-platform native OS credential storage.
/// </summary>
public abstract class NativeSecretsBase : INativeSecrets
{
    /// <inheritdoc />
    public abstract void SetSecret(string service, string account, string secret);

    /// <inheritdoc />
    public abstract string? GetSecret(string service, string account);

    /// <inheritdoc />
    public abstract void DeleteSecret(string service, string account);

    /// <inheritdoc />
    public virtual bool SecretExists(string service, string account) => GetSecret(service, account) is not null;

    /// <inheritdoc />
    public virtual Task SetSecretAsync(string service, string account, string secret, CancellationToken ct = default)
        => Task.Run(() => SetSecret(service, account, secret), ct);

    /// <inheritdoc />
    public virtual Task<string?> GetSecretAsync(string service, string account, CancellationToken ct = default)
        => Task.Run(() => GetSecret(service, account), ct);

    /// <inheritdoc />
    public virtual Task DeleteSecretAsync(string service, string account, CancellationToken ct = default)
        => Task.Run(() => DeleteSecret(service, account), ct);

    /// <inheritdoc />
    public virtual Task<bool> SecretExistsAsync(string service, string account, CancellationToken ct = default)
        => Task.Run(() => SecretExists(service, account), ct);

    /// <summary>
    /// Creates a new instance of the default cross-platform native secrets' provider.
    /// </summary>
    /// <param name="options">Optional configuration settings for the provider.</param>
    /// <returns>An initialized <see cref="NativeSecretsBase"/> instance.</returns>
    public static NativeSecretsBase Create(NativeSecretsOptions? options = null)
        => new NativeSecretsProvider(options ?? new NativeSecretsOptions());
}