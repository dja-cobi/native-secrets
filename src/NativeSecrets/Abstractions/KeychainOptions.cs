using Microsoft.Extensions.Logging;

namespace NativeSecrets.Abstractions;

/// <summary>Options for creating a keychain store.</summary>
public sealed class KeychainOptions
{
    /// <summary>Forces the encrypted file fallback, bypassing native stores.</summary>
    public bool ForceFallback { get; set; }
    
    /// <summary>Directory for the fallback store. Defaults to <c>%APPDATA%/SecureVault</c>.</summary>
    public string? FallbackDirectory { get; set; }
    
    /// <summary>Custom fallback implementation (e.g. for tests).</summary>
    public IKeychainStore? FallbackStore { get; set; }
    
    /// <summary>Logger. Defaults to <see cref="Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance"/>.</summary>
    public ILogger? Logger { get; init; }

    /// <summary>Timeout for <see cref="IKeychainStore.IsAvailable(TimeSpan?)"/>. Defaults to 5 seconds.</summary>
    public TimeSpan AvailabilityTimeout { get; init; } = TimeSpan.FromSeconds(5);
}