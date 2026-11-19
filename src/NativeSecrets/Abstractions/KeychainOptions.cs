namespace NativeSecrets.Abstractions;

public sealed class KeychainOptions
{
    public bool ForceFallback { get; set; }
    public string? FallbackDirectory { get; set; }
    public IKeychainStore? FallbackStore { get; set; }
}