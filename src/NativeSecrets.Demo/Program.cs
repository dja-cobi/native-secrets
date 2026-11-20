using NativeSecrets.Core;

var store = KeychainFactory.Instance;
Console.WriteLine($"OS: {Environment.OSVersion}");
Console.WriteLine($"Fallback: {KeychainFactory.IsUsingFallback}");

const string pkg = "org.nativesecrets.test";
const string svc = "smoke-test";
const string usr = "user1";

await store.SetPasswordAsync(pkg, svc, usr, "hello-world-123");
var val = await store.GetPasswordAsync(pkg, svc, usr);
Console.WriteLine($"Read: {val}"); // Должно вывести: hello-world-123

var del = await store.DeletePasswordAsync(pkg, svc, usr);
var afterDel = await store.GetPasswordAsync(pkg, svc, usr);
Console.WriteLine($"Deleted: {del}, After delete: {afterDel ?? "null"}"); // Deleted: True, After delete: null