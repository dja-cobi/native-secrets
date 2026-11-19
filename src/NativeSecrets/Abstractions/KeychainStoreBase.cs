namespace NativeSecrets.Abstractions;

/// <summary>
/// Base class: synchronous members are abstract; asynchronous overloads
/// default to <see cref="Task.Run(Action, CancellationToken)"/>.
/// </summary>
internal abstract class KeychainStoreBase : IKeychainStore
{
    private bool _disposed;
    
    /// <inheritdoc />
    public abstract bool IsAvailable(TimeSpan? timeout = null);

    /// <inheritdoc />
    public abstract void SetPassword(string package, string service, string user, string password);

    /// <inheritdoc />
    public abstract string? GetPassword(string package, string service, string user);

    /// <inheritdoc />
    public abstract bool DeletePassword(string package, string service, string user);

    /// <inheritdoc />
    public virtual Task SetPasswordAsync(string package, string service, string user, string password, CancellationToken ct = default)
        => Task.Run(() => SetPassword(package, service, user, password), ct);

    /// <inheritdoc />
    public virtual Task<string?> GetPasswordAsync(string package, string service, string user, CancellationToken ct = default)
        => Task.Run(() => GetPassword(package, service, user), ct);

    /// <inheritdoc />
    public virtual Task<bool> DeletePasswordAsync(string package, string service, string user, CancellationToken ct = default)
        => Task.Run(() => DeletePassword(package, service, user), ct);

    /// <inheritdoc cref="_disposed" />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    /// <summary>Override to release native resources.</summary>
    protected virtual void DisposeCore() { }
}