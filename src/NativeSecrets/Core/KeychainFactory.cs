using NativeSecrets.Abstractions;
using NativeSecrets.Fallback;
using NativeSecrets.Platforms;

namespace NativeSecrets.Core;

public static class KeychainFactory
{
    private static readonly Lazy<KeychainStoreProvider> InstanceHolder =
        new(() => CreateProvider(), LazyThreadSafetyMode.ExecutionAndPublication);
    

    public static IKeychainStore Instance => InstanceHolder.Value;
    public static bool IsUsingFallback => InstanceHolder.Value.IsUsingFallback;

    public static KeychainStoreProvider CreateProvider(KeychainOptions? options = null)
    {
        options ??= new KeychainOptions();

        if (!options.ForceFallback)
        {
            var native = GetPlatformStore();
            if (native.IsAvailable())
                return new KeychainStoreProvider(native, usingFallback: false);
        }

        var fallback = options.FallbackStore ?? new EncryptedFileFallbackStore(options.FallbackDirectory);
        return new KeychainStoreProvider(fallback, usingFallback: true);
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