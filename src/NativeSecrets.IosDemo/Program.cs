using NativeSecrets;

try
{
    var store = KeychainFactory.Instance;
    Console.WriteLine($"[NativeSecrets.IosDemo] Store: {store.GetType().Name}, Fallback: {KeychainFactory.IsUsingFallback}");

    if (KeychainFactory.IsUsingFallback)
        throw new InvalidOperationException("Fallback store was used instead of IosKeychain!");

    const string pkg = "org.nativesecrets.iosdemo";
    const string svc = "ios-test";
    const string usr = "djacobi";
    const string secret = "iOS_KeyChain_Secret_123!";

    store.SetPassword(pkg, svc, usr, secret);
    var loaded = store.GetPassword(pkg, svc, usr);

    if (loaded != secret)
        throw new InvalidOperationException($"Expected '{secret}', got '{loaded ?? "null"}'");

    if (!store.DeletePassword(pkg, svc, usr))
        throw new InvalidOperationException("Failed to delete password");

    if (store.GetPassword(pkg, svc, usr) != null)
        throw new InvalidOperationException("Password still exists after deletion");

    Console.WriteLine("[NativeSecrets.IosDemo] SUCCESS: Apple SecKeyChain works properly!");
    Environment.Exit(0);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[NativeSecrets.IosDemo] ERROR: {ex}");
    Environment.Exit(1);
}
