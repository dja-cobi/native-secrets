namespace NativeSecrets.Abstractions;

/// <summary>
/// Abstraction over a platform-native secret storage.
/// </summary>
/// <remarks>
/// All implementations must be thread-safe. Synchronous members are kept for
/// backward compatibility; asynchronous overloads are preferred for UI contexts.
/// </remarks>
public interface IKeychainStore : IDisposable
{
    /// <summary>
    /// Checks whether the underlying store is usable. May perform an expensive round-trip.
    /// </summary>
    /// <param name="timeout">Maximum time to wait. Defaults to 5 seconds.</param>
    /// <returns><c>true</c> if the store is usable; otherwise <c>false</c>.</returns>
    bool IsAvailable(TimeSpan? timeout = null);
    
    /// <summary>Stores or overwrites a secret.</summary>
    /// <param name="package">Unique application identifier, e.g. <c>com.example.MyApp</c>.</param>
    /// <param name="service">Logical group of secrets, e.g. <c>ApiKeys</c>.</param>
    /// <param name="user">Account identifier within the service. Empty string if not needed.</param>
    /// <param name="password">The secret. Empty string is allowed.</param>
    void SetPassword(string package, string service, string user, string password);
    
    /// <summary>Returns the secret, or <c>null</c> if the entry does not exist.</summary>
    string? GetPassword(string package, string service, string user);
    
    /// <summary>Deletes the secret. Returns <c>true</c> if the entry existed.</summary>
    bool DeletePassword(string package, string service, string user);
    
    /// <summary>Asynchronously stores or overwrites a secret.</summary>
    Task SetPasswordAsync(string package, string service, string user, string password, CancellationToken ct = default);

    /// <summary>Asynchronously returns the secret, or <c>null</c>.</summary>
    Task<string?> GetPasswordAsync(string package, string service, string user, CancellationToken ct = default);

    /// <summary>Asynchronously deletes the secret.</summary>
    Task<bool> DeletePasswordAsync(string package, string service, string user, CancellationToken ct = default);
}