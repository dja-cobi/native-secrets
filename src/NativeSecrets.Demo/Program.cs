using NativeSecrets;

var store = KeychainFactory.Instance;
bool fallback = KeychainFactory.IsUsingFallback;

if (store.IsAvailable())
{
    store.SetPassword("MyApp", "ApiToken", "user@example.com", "super-secret");
    string? pwd = store.GetPassword("MyApp", "ApiToken", "user@example.com");
    Console.WriteLine(pwd);
    bool removed = store.DeletePassword("MyApp", "ApiToken", "user@example.com");
    Console.WriteLine(removed);
}