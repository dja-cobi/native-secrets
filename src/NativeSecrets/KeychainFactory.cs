namespace NativeSecrets;

public class KeychainFactory
{
    private static readonly Lazy<IKeychainStore> _instance = new(CreateStore, LazyThreadSafetyMode.ExecutionAndPublication);
    public static IKeychainStore Instance => _instance.Value;
    public static bool IsUsingFallback {get; private set;}

    private static IKeychainStore CreateStore()
    {
        var native = GetPlatformStore();
        if (native.IsAvailable())
            return native;

        IsUsingFallback = true;
        return new EncryptedFileFallbackStore();
    }

    private static IKeychainStore GetPlatformStore()
    {
#if IOS || MACCATALYST
        return new IosKeychain();
#elif ANDROID
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

    
//     private static IKeychainStore GetPlatformStore()
//     {
// #if WINDOWS
//         return new WindowsKeychain();
// #elif IOS
//         return new IosKeychain();
// #elif ANDROID
//         return new AndroidKeychain();
// #elif MACOS
//         return new MacKeychain();
// #elif LINUX
//         return new LinuxKeychain();
// #else
//         return new UnsupportedKeychain();
// #endif
//     }

    private sealed class UnsupportedKeychain : IKeychainStore
    {
        public bool IsAvailable() => false;
        public void SetPassword(string package, string service, string user, string password)
            => throw new PlatformNotSupportedException();
        public string? GetPassword(string package, string service, string user) => null;
        public bool DeletePassword(string package, string service, string user) => false;
    }
}