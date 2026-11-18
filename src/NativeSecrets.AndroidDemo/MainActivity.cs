using Android.App;
using Android.OS;
using Android.Util;
using Android.Widget;
using NativeSecrets;

namespace NativeSecrets.AndroidDemo;

[Activity(Label = "@string/app_name", MainLauncher = true)]
public class MainActivity : Activity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        var textView = new TextView(this)
        {
            TextSize = 18f
        };
        textView.SetPadding(40, 80, 40, 40);
        SetContentView(textView);

        try
        {
            var store = KeychainFactory.Instance;
            bool requireNative = Intent?.GetBooleanExtra("require_native", false) ?? false;

            Log.Info("NativeSecrets", $"Store: {store.GetType().Name}, Fallback: {KeychainFactory.IsUsingFallback}, RequireNative: {requireNative}");

            if (requireNative && KeychainFactory.IsUsingFallback)
                throw new InvalidOperationException("Fallback store was used instead of AndroidKeychain!");

            const string pkg = "org.nativesecrets.demo";
            const string svc = "android-test";
            const string usr = "djacobi";
            const string secret = "Android_KeyStore_Secret_123!";

            store.SetPassword(pkg, svc, usr, secret);
            var loaded = store.GetPassword(pkg, svc, usr);

            if (loaded != secret)
                throw new InvalidOperationException($"Expected '{secret}', got '{loaded ?? "null"}'");

            if (!store.DeletePassword(pkg, svc, usr))
                throw new InvalidOperationException("Failed to delete password");

            if (store.GetPassword(pkg, svc, usr) != null)
                throw new InvalidOperationException("Password still exists after deletion");

            const string okMsg = "SUCCESS: Secret storage works properly!";
            Log.Info("NativeSecrets", okMsg);
            textView.Text = $"Store: {store.GetType().Name}\nFallback: {KeychainFactory.IsUsingFallback}\n\n{okMsg}";
        }
        catch (Exception ex)
        {
            Log.Error("NativeSecrets", ex.ToString());
            textView.TextSize = 12f;
            textView.Text = $"ERROR:\n{ex}";
        }
    }
}

