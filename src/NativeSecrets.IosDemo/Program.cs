using Foundation;
using NativeSecrets.Core;
using UIKit;

UIApplication.Main(args, null, typeof(AppDelegate));

[Register("AppDelegate")]
public class AppDelegate : UIApplicationDelegate
{
    public override bool FinishedLaunching(UIApplication application, NSDictionary? launchOptions)
    {
        const string resultFile = "/tmp/ios_test_result.txt";
        try
        {
            var store = KeychainFactory.Instance;
            var info = $"Store: {store.GetType().Name}, Fallback: {KeychainFactory.IsUsingFallback}";

            if (KeychainFactory.IsUsingFallback)
                throw new InvalidOperationException($"Fallback store was used instead of IosKeychain! ({info})");

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

            File.WriteAllText(resultFile, $"SUCCESS: Apple SecKeyChain works properly! ({info})");
        }
        catch (Exception ex)
        {
            File.WriteAllText(resultFile, $"ERROR: {ex}");
        }

        return true;
    }
}