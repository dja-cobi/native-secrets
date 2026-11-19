namespace NativeSecrets.Abstractions;

/// <summary>Unified argument validation for all implementations.</summary>
internal static class KeychainGuard
{
    /// <summary>Validates key components (package, service, user).</summary>
    public static void ValidateKey(string package, string service, string user)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(package);
        ArgumentException.ThrowIfNullOrWhiteSpace(service);
        ArgumentNullException.ThrowIfNull(user);
    }

    /// <summary>Validates the password argument (non-null; empty is allowed).</summary>
    public static void ValidatePassword(string password) => ArgumentNullException.ThrowIfNull(password);
}