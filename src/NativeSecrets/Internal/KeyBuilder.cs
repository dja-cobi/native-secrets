using System.Text;

namespace NativeSecrets.Internal;

/// <summary>Single source of truth for identifier construction across platforms.</summary>
internal static class KeyBuilder
{
    /// <summary>Escapes <c>%</c> and <c>/</c> so the separator cannot appear inside components.</summary>
    private static string Escape(string s)
        => s.Replace("%", "%25", StringComparison.Ordinal)
            .Replace("/", "%2F", StringComparison.Ordinal);
    
    /// <summary>
    /// Builds <c>package/service/user</c> with escaping. Suitable for Windows Credential Manager,
    /// iOS Keychain service, and macOS Keychain service.
    /// </summary>
    public static string BuildTarget(string package, string service, string user)
        => $"{Escape(package)}/{Escape(service)}/{Escape(user)}";

    /// <summary>Builds <c>package/service</c> with escaping. Suitable for iOS/macOS service fields.</summary>
    public static string BuildService(string package, string service)
        => $"{Escape(package)}/{Escape(service)}";

    /// <summary>Builds a NUL-separated identifier. Suitable for Android SharedPreferences keys and the file fallback.</summary>
    public static string BuildNulSeparated(string package, string service, string user)
        => $"{package}\0{service}\0{user}";

    /// <summary>Builds a Base64-encoded NUL-separated identifier.</summary>
    public static string BuildNulSeparatedBase64(string package, string service, string user)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(BuildNulSeparated(package, service, user)));
}