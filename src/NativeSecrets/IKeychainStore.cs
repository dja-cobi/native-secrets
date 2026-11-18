namespace NativeSecrets;

public interface IKeychainStore
{
    bool IsAvailable();
    void SetPassword(string package, string service, string user, string password);
    string? GetPassword(string package, string service, string user);
    bool DeletePassword(string package, string service, string user);
}