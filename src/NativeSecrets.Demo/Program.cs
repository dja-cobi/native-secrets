using NativeSecrets;
using NativeSecrets.Core;

var store = KeychainFactory.Instance;
Console.WriteLine($"OS: {Environment.OSVersion}");
Console.WriteLine($"Store: {store.GetType().Name}, Fallback: {KeychainFactory.IsUsingFallback}");

if (KeychainFactory.IsUsingFallback)
{
    Console.Error.WriteLine("ERROR: Fallback store was used instead of native OS keychain!");
    return 1;
}

const string pkg = "org.nativesecrets.ci";
const string svc = "windows-check";
const string usr = "test-user";
const string secret = "P@ssw0rd_Win_123!";

store.SetPassword(pkg, svc, usr, secret);
var loaded = store.GetPassword(pkg, svc, usr);

if (loaded != secret)
{
    Console.Error.WriteLine($"ERROR: Expected '{secret}', got '{loaded ?? "null"}'");
    return 1;
}

if (!store.DeletePassword(pkg, svc, usr))
{
    Console.Error.WriteLine("ERROR: Failed to delete secret");
    return 1;
}

if (store.GetPassword(pkg, svc, usr) != null)
{
    Console.Error.WriteLine("ERROR: Secret still exists after deletion");
    return 1;
}

Console.WriteLine("SUCCESS: Windows Credential Manager works properly!");
return 0;



// using NativeSecrets;
//
// var store = KeychainFactory.Instance;
// bool fallback = KeychainFactory.IsUsingFallback;
//
// if (store.IsAvailable())
// {
//     store.SetPassword("MyApp", "ApiToken", "user@example.com", "super-secret");
//     string? pwd = store.GetPassword("MyApp", "ApiToken", "user@example.com");
//     Console.WriteLine(pwd);
//     bool removed = store.DeletePassword("MyApp", "ApiToken", "user@example.com");
//     Console.WriteLine(removed);
// }