using NativeSecrets.Abstractions;

namespace NativeSecrets.Platforms;

/// <summary>No-op store for unsupported platforms.</summary>
internal sealed class UnsupportedKeychain : KeychainStoreBase
{
    /// <inheritdoc />
    public override bool IsAvailable(TimeSpan? timeout = null) => false;

    /// <inheritdoc />
    public override void SetPassword(string package, string service, string user, string password)
        => throw new PlatformNotSupportedException();

    /// <inheritdoc />
    public override string? GetPassword(string package, string service, string user) => null;

    /// <inheritdoc />
    public override bool DeletePassword(string package, string service, string user) => false;
}