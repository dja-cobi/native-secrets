using Microsoft.Extensions.Logging;
using NativeSecrets.Abstractions;
using NativeSecrets.Fallback;
using NativeSecrets.Platforms;

namespace NativeSecrets.Core;

/// <summary>
/// Static entry point for use without DI. Lazily builds a single
/// <see cref="KeychainStoreProvider"/>.
/// </summary>
public static class KeychainFactory
{
    private static readonly Lazy<KeychainStoreProvider> SharedProvider =
        new(() => CreateProvider(), LazyThreadSafetyMode.ExecutionAndPublication);
    
    /// <summary>Shared store instance (native if available, otherwise fallback).</summary>
    public static IKeychainStore Instance => SharedProvider.Value;
    
    /// <summary>Whether the shared store is the fallback.</summary>
    public static bool IsUsingFallback => SharedProvider.Value.IsUsingFallback;

    /// <summary>
    /// Creates a new provider. Note: constructing the fallback store is expensive
    /// (PBKDF2 with 200k iterations) — call once and cache.
    /// </summary>
    /// <param name="options">Optional configuration.</param>
    public static KeychainStoreProvider CreateProvider(KeychainOptions? options = null)
    {
        options ??= new KeychainOptions();
        var logger = options.Logger;

        if (!options.ForceFallback)
        {
            try
            {
                var native = GetPlatformStore();
                if (native.IsAvailable(options.AvailabilityTimeout))
                {
                    logger?.LogInformation("Using native keychain store: {Store}.", native.GetType().Name);
                    return new KeychainStoreProvider(native, usingFallback: false, logger);
                }
                logger?.LogWarning("Native keychain store {Store} is not available; falling back.", native.GetType().Name);
            }
            catch (Exception ex)
            {
                logger?.LogWarning(ex, "Native keychain probe failed; falling back.");
            }
        }

        var fallback = options.FallbackStore ?? new EncryptedFileFallbackStore(options.FallbackDirectory);
        logger?.LogInformation("Using encrypted file fallback store.");
        return new KeychainStoreProvider(fallback, usingFallback: true, logger);
    }

    private static IKeychainStore GetPlatformStore()
    {
#if IOS || __IOS__ || MACCATALYST || __MACCATALYST__
        return new IosKeychain();
#elif ANDROID || __ANDROID__
        return new AndroidKeychain();
#else
        if (OperatingSystem.IsWindows())
            return new WindowsKeychain();

        if (OperatingSystem.IsMacOS())
            return new MacKeychain();

        if (OperatingSystem.IsLinux())
            return new LinuxKeychain();

        return new UnsupportedKeychain();
#endif
    }
}

// using NativeSecrets.Abstractions;
// using NativeSecrets.Fallback;
// using NativeSecrets.Platforms;
//
// namespace NativeSecrets.Core;
//
// public static class KeychainFactory
// {
//     private static readonly Lazy<KeychainStoreProvider> _instance = new(CreateProvider, LazyThreadSafetyMode.ExecutionAndPublication);
//     public static IKeychainStore Instance => _instance.Value;
//     public static bool IsUsingFallback => _instance.Value.IsUsingFallback;
//
//     public static KeychainStoreProvider CreateProvider(KeychainOptions? options = null)
//     {
//         options ??= new KeychainOptions();
//
//         if (!options.ForceFallback)
//         {
//             var native = GetPlatformStore();
//             if (native.IsAvailable())
//                 return new KeychainStoreProvider(native, usingFallback:false);
//         }
//         
//         var fallback = options.FallbackStore ?? new EncryptedFileFallbackStore(options.FallbackDirectory);
//         return new KeychainStoreProvider(fallback, usingFallback: true);
//     }
//
//     private static IKeychainStore GetPlatformStore()
//     {
// #if IOS || __IOS__ || MACCATALYST || __MACCATALYST__
//         return new IosKeychain();
// #elif ANDROID || __ANDROID__
//         return new AndroidKeychain();
// #else
//         if (OperatingSystem.IsWindows())
//             return new Platforms.WindowsKeychain();
//
//         if (OperatingSystem.IsMacOS())
//             return new Platforms.MacKeychain();
//
//         if (OperatingSystem.IsLinux())
//             return new Platforms.LinuxKeychain();
//
//         return new UnsupportedKeychain();
// #endif
//     }
// }