using NativeSecrets.Abstractions;

namespace NativeSecrets.Core;

public sealed class KeychainStoreProvider(IKeychainStore store, bool usingFallback) : IKeychainStore
{
    private readonly IKeychainStore _store = store ?? throw new ArgumentNullException(nameof(store));
    public bool IsUsingFallback { get; } = usingFallback;

    public bool IsAvailable() => _store.IsAvailable();

    public void SetPassword(string package, string service, string user, string password) => 
        _store.SetPassword(package, service, user, password);

    public string? GetPassword(string package, string service, string user) => 
        _store.GetPassword(package, service, user);

    public bool DeletePassword(string package, string service, string user) => 
        _store.DeletePassword(package, service, user);
}