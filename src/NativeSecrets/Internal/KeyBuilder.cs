using System.Text;

namespace NativeSecrets.Internal;

internal static class KeyBuilder
{
    public static string BuildTarget(string package, string service, string user) => $"{package}/{service}/{user}";
    
    public static string BuildService(string package, string service) => $"{package}/{service}";
    public static string BuildNulSeparated(string package, string service, string user)
        => $"{package}\0{service}\0{user}";

    public static string BuildNulSeparatedBase64(string package, string service, string user)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(BuildNulSeparated(package, service, user)));
}