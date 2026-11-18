#if ANDROID
using System.Security.Cryptography;
using System.Text;
using Android.App;
using Android.Content;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;
using Microsoft.Maui.ApplicationModel;

namespace SecureVault;

internal sealed class AndroidKeychain : IKeychainStore
{
    private const string KeyAlias = "SecureVault.MasterKey";
    private const string PrefsName = "securevault";
    private const string AndroidKeyStore = "AndroidKeyStore";

    private static ISharedPreferences GetPrefs(Context ctx)
        => ctx.GetSharedPreferences(PrefsName, FileCreationMode.Private)!;

    private static KeyStore GetKeyStore()
    {
        var ks = KeyStore.GetInstance(AndroidKeyStore)!;
        ks.Load(null);
        return ks;
    }

    private static ISecretKey GetOrCreateKey()
    {
        var ks = GetKeyStore();
        if (ks.ContainsAlias(KeyAlias))
        {
            var existing = ks.GetKey(KeyAlias, null) as ISecretKey;
            if (existing != null) return existing;
        }

        var generator = KeyGenerator.GetInstance(
            KeyProperties.KeyAlgorithmAes!, AndroidKeyStore)!;
        var builder = new KeyGenParameterSpec.Builder(
                KeyAlias,
                KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)!
            .SetBlockModes(KeyProperties.BlockModeGcm!)!
            .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone!)!
            .SetRandomizedEncryptionRequired(true)!;
        generator.Init(builder.Build());
        return generator.GenerateKey()!;
    }

    public bool IsAvailable()
    {
        try
        {
            var ctx = Android.App.Application.Context;
            if (ctx == null) return false;
            _ = GetPrefs(ctx);
            _ = GetOrCreateKey();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string MakeKey(string package, string service, string user)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes($"{package}\u0000{service}\u0000{user}"));

    public void SetPassword(string package, string service, string user, string password)
    {
        var key = GetOrCreateKey();
        var cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
        cipher.Init(Javax.Crypto.CipherMode.EncryptMode, key);
        byte[] plain = Encoding.UTF8.GetBytes(password);
        byte[] cipherBytes = cipher.DoFinal(plain)!;
        byte[] iv = cipher.GetIV()!;

        byte[] combined = new byte[iv.Length + cipherBytes.Length];
        Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
        Buffer.BlockCopy(cipherBytes, 0, combined, iv.Length, cipherBytes.Length);

        var prefs = GetPrefs(Android.App.Application.Context);
        using var editor = prefs.Edit()!;
        editor.PutString(MakeKey(package, service, user), Convert.ToBase64String(combined))!;
        editor.Apply();
    }

    public string? GetPassword(string package, string service, string user)
    {
        var prefs = GetPrefs(Android.App.Application.Context);
        string? stored = prefs.GetString(MakeKey(package, service, user), null);
        if (string.IsNullOrEmpty(stored)) return null;

        byte[] combined = Convert.FromBase64String(stored);
        const int tagLen = 16;
        int ivLen = combined.Length - tagLen - (combined.Length - 12 - tagLen > 0 ? combined.Length - 12 - tagLen : 0);
        // IV в AES/GCM из Android обычно 12 байт; однако берём точно сохранённый в cipher при записи.
        // Т.к. IV хранится первым, для расшифровки нам нужно знать его длину — используем 12 (стандарт AndroidKeyStore).
        ivLen = 12;
        byte[] iv = new byte[ivLen];
        byte[] cipherBytes = new byte[combined.Length - ivLen];
        Buffer.BlockCopy(combined, 0, iv, 0, ivLen);
        Buffer.BlockCopy(combined, ivLen, cipherBytes, 0, cipherBytes.Length);

        var key = GetOrCreateKey();
        var cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
        cipher.Init(Javax.Crypto.CipherMode.DecryptMode, key, new GCMParameterSpec(128, iv));
        byte[] plain = cipher.DoFinal(cipherBytes)!;
        return Encoding.UTF8.GetString(plain);
    }

    public bool DeletePassword(string package, string service, string user)
    {
        var prefs = GetPrefs(Android.App.Application.Context);
        string key = MakeKey(package, service, user);
        if (!prefs.Contains(key)) return false;
        using var editor = prefs.Edit()!;
        editor.Remove(key)!;
        editor.Apply();
        return true;
    }
}
#endif