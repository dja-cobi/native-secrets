using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NativeSecrets.Abstractions;

namespace NativeSecrets.Core;

/// <summary>
/// Thread-safe provider that delegates to the selected store (native or fallback).
/// Registered in DI as the single <see cref="IKeychainStore"/>.
/// </summary>
public sealed class KeychainStoreProvider : IKeychainStore
{
    private readonly IKeychainStore _store;
    private readonly ILogger _logger;

    /// <summary>Creates a provider.</summary>
    /// <param name="store">The inner store.</param>
    /// <param name="usingFallback">Whether the inner store is the fallback.</param>
    /// <param name="logger">Optional logger.</param>
    public KeychainStoreProvider(IKeychainStore store, bool usingFallback, ILogger? logger = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        IsUsingFallback = usingFallback;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>Whether the active store is the encrypted file fallback.</summary>
    public bool IsUsingFallback { get; }

    /// <inheritdoc />
    public bool IsAvailable(TimeSpan? timeout = null) => _store.IsAvailable(timeout);

    /// <inheritdoc />
    public void SetPassword(string package, string service, string user, string password)
        => _store.SetPassword(package, service, user, password);

    /// <inheritdoc />
    public string? GetPassword(string package, string service, string user)
        => _store.GetPassword(package, service, user);

    /// <inheritdoc />
    public bool DeletePassword(string package, string service, string user)
        => _store.DeletePassword(package, service, user);

    /// <inheritdoc />
    public Task SetPasswordAsync(string package, string service, string user, string password, CancellationToken ct = default)
        => _store.SetPasswordAsync(package, service, user, password, ct);

    /// <inheritdoc />
    public Task<string?> GetPasswordAsync(string package, string service, string user, CancellationToken ct = default)
        => _store.GetPasswordAsync(package, service, user, ct);

    /// <inheritdoc />
    public Task<bool> DeletePasswordAsync(string package, string service, string user, CancellationToken ct = default)
        => _store.DeletePasswordAsync(package, service, user, ct);

    /// <inheritdoc />
    public void Dispose()
    {
        try
        {
            _store.Dispose();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error disposing keychain store.");
        }
    }
    
    // private readonly IKeychainStore _store = store ?? throw new ArgumentNullException(nameof(store));
    // public bool IsUsingFallback { get; } = usingFallback;
    //
    // public bool IsAvailable() => _store.IsAvailable();
    //
    // public void SetPassword(string package, string service, string user, string password) => 
    //     _store.SetPassword(package, service, user, password);
    //
    // public string? GetPassword(string package, string service, string user) => 
    //     _store.GetPassword(package, service, user);
    //
    // public bool DeletePassword(string package, string service, string user) => 
    //     _store.DeletePassword(package, service, user);
}