using NativeSecrets.Core;

bool requireNative = args.Contains("--require-native");

var store = KeychainFactory.Instance;
Console.WriteLine($"OS: {Environment.OSVersion}");
Console.WriteLine($"Fallback: {KeychainFactory.IsUsingFallback}, RequireNative: {requireNative}");

if (requireNative && KeychainFactory.IsUsingFallback)
{
    Console.Error.WriteLine("ERROR: Expected native OS store, but fallback was used!");
    return 1;
}

const string pkg = "org.nativesecrets.ci";
const string svc = "smoke-test";
const string usr = "ci-user";
const string secret = "Ci_Secret_Check_2026!";

await store.SetPasswordAsync(pkg, svc, usr, secret);
var val = await store.GetPasswordAsync(pkg, svc, usr);
Console.WriteLine($"Read: {val}");

if (val != secret)
{
    Console.Error.WriteLine($"ERROR: Read mismatch! Expected '{secret}', got '{val ?? "null"}'");
    return 1;
}

var del = await store.DeletePasswordAsync(pkg, svc, usr);
var afterDel = await store.GetPasswordAsync(pkg, svc, usr);
Console.WriteLine($"Deleted: {del}, After delete: {afterDel ?? "null"}");

if (!del || afterDel != null)
{
    Console.Error.WriteLine("ERROR: Secret was not properly deleted!");
    return 1;
}

Console.WriteLine("ALL CHECKS PASSED!");
return 0;