using NativeSecrets.Abstractions;

namespace NativeSecrets.Platforms;

internal sealed class UnsupportedKeychain : IKeychainStore
{
    public bool IsAvailable() => false;
    public void SetPassword(string package, string service, string user, string password) => throw new PlatformNotSupportedException();
    public string? GetPassword(string package, string service, string user) => null;
    public bool DeletePassword(string package, string service, string user) => false;
}