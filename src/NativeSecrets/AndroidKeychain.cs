#if ANDROID
using System.Security.Cryptography;
using System.Text;
using Android.App;
using Android.Content;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;

namespace NativeSecrets;

internal sealed class AndroidKeychain : IKeychainStore
{
    private const string KeyAlias = "NativeSecrets.MasterKey";
    private const string PrefsName = "nativesecrets_vault";
    private const string AndroidKeyStore = "AndroidKeyStore";
    private const int GcmTagLengthBits = 128;
    private const int GcmTagLengthBytes = 16;

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
            if (ks.GetKey(KeyAlias, null) is ISecretKey existing)
                return existing;
        }

        var generator = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes!, AndroidKeyStore)!;
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
            if (!OperatingSystem.IsAndroidVersionAtLeast(23))
                return false;

            var ctx = Application.Context;
            if (ctx == null) return false;

            _ = GetPrefs(ctx);
            _ = GetKeyStore();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string MakeKey(string package, string service, string user)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes($"{package}\0{service}\0{user}"));

    public void SetPassword(string package, string service, string user, string password)
    {
        var key = GetOrCreateKey();
        var cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
        cipher.Init(CipherMode.EncryptMode, key);

        byte[] plain = Encoding.UTF8.GetBytes(password);
        try
        {
            byte[] cipherBytes = cipher.DoFinal(plain)!;
            byte[] iv = cipher.GetIV()!;

            // Формат: [1 байт длина IV] + [IV] + [CipherText + GCM Tag]
            byte[] combined = new byte[1 + iv.Length + cipherBytes.Length];
            combined[0] = (byte)iv.Length;
            Buffer.BlockCopy(iv, 0, combined, 1, iv.Length);
            Buffer.BlockCopy(cipherBytes, 0, combined, 1 + iv.Length, cipherBytes.Length);

            var prefs = GetPrefs(Application.Context);
            using var editor = prefs.Edit()!;
            editor.PutString(MakeKey(package, service, user), Convert.ToBase64String(combined))!;
            editor.Apply();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public string? GetPassword(string package, string service, string user)
    {
        var prefs = GetPrefs(Application.Context);
        string? stored = prefs.GetString(MakeKey(package, service, user), null);
        if (string.IsNullOrEmpty(stored)) return null;

        byte[] combined = Convert.FromBase64String(stored);
        if (combined.Length < 2) return null;

        int ivLen = combined[0];
        if (combined.Length < 1 + ivLen + GcmTagLengthBytes)
            return null;

        byte[] iv = new byte[ivLen];
        byte[] cipherBytes = new byte[combined.Length - 1 - ivLen];
        Buffer.BlockCopy(combined, 1, iv, 0, ivLen);
        Buffer.BlockCopy(combined, 1 + ivLen, cipherBytes, 0, cipherBytes.Length);

        var key = GetOrCreateKey();
        var cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
        cipher.Init(CipherMode.DecryptMode, key, new GCMParameterSpec(GcmTagLengthBits, iv));

        byte[] plain = cipher.DoFinal(cipherBytes)!;
        try
        {
            return Encoding.UTF8.GetString(plain);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public bool DeletePassword(string package, string service, string user)
    {
        var prefs = GetPrefs(Application.Context);
        string key = MakeKey(package, service, user);
        if (!prefs.Contains(key)) return false;

        using var editor = prefs.Edit()!;
        editor.Remove(key)!;
        editor.Apply();
        return true;
    }
}
#endif
