#if ANDROID || __ANDROID__
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Android.App;
using Android.Content;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;
using NativeSecrets.Abstractions;
using NativeSecrets.Internal;

namespace NativeSecrets.Platforms;

internal sealed class AndroidKeychain : IKeychainStore
{
    private const string KeyAlias = "NativeSecrets.MasterKey";
    private const string PrefsName = "nativesecrets_vault";
    private const string AndroidKeyStore = "AndroidKeyStore";
    private const int GcmTagLengthBits = 128;

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
            .SetKeySize(256)!
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

            const string probePkg = "__nativesecrets_probe__";
            const string probeSvc = "__probe__";
            const string probeUsr = "__probe__";
            const string probeVal = "probe_ok";

            SetPassword(probePkg, probeSvc, probeUsr, probeVal);
            var roundtrip = GetPassword(probePkg, probeSvc, probeUsr);
            DeletePassword(probePkg, probeSvc, probeUsr);

            return roundtrip == probeVal;
        }
        catch
        {
            return false;
        }
    }

    public void SetPassword(string package, string service, string user, string password)
    {
        var key = GetOrCreateKey();
        var cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
        cipher.Init(Javax.Crypto.CipherMode.EncryptMode, key);

        byte[] plain = Encoding.UTF8.GetBytes(password);
        try
        {
            byte[] cipherBytes = cipher.DoFinal(plain)!;
            byte[] iv = cipher.GetIV()!;

            string payload = $"{Convert.ToBase64String(iv)}:{Convert.ToBase64String(cipherBytes)}";

            var prefs = GetPrefs(Application.Context);
            using var editor = prefs.Edit()!;
            editor.PutString(KeyBuilder.BuildNulSeparatedBase64(package, service, user), payload);
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
        string? stored = prefs.GetString(KeyBuilder.BuildNulSeparatedBase64(package, service, user), null);
        if (string.IsNullOrEmpty(stored)) return null;

        var parts = stored.Split(':');
        if (parts.Length != 2) return null;

        byte[] iv = Convert.FromBase64String(parts[0]);
        byte[] cipherBytes = Convert.FromBase64String(parts[1]);

        var key = GetOrCreateKey();
        var cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
        using var spec = new GCMParameterSpec(GcmTagLengthBits, iv, 0, iv.Length);
        cipher.Init(Javax.Crypto.CipherMode.DecryptMode, key, spec);

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
        string key = KeyBuilder.BuildNulSeparatedBase64(package, service, user);
        if (!prefs.Contains(key)) return false;

        using var editor = prefs.Edit()!;
        editor.Remove(key);
        editor.Apply();
        return true;
    }
}
#endif

// #if ANDROID || __ANDROID__
// using System.Linq;
// using System.Security.Cryptography;
// using System.Text;
// using Android.App;
// using Android.Content;
// using Android.Security.Keystore;
// using Java.Security;
// using Javax.Crypto;
// using Javax.Crypto.Spec;
// using NativeSecrets.Internal;
//
// namespace NativeSecrets.Platforms;
//
// internal sealed class AndroidKeychain : IKeychainStore
// {
//     private const string KeyAlias = "NativeSecrets.MasterKey";
//     private const string PrefsName = "nativesecrets_vault";
//     private const string AndroidKeyStore = "AndroidKeyStore";
//     private const int GcmTagLengthBits = 128;
//
//     private static ISharedPreferences GetPrefs(Context ctx)
//         => ctx.GetSharedPreferences(PrefsName, FileCreationMode.Private)!;
//
//     private static KeyStore GetKeyStore()
//     {
//         var ks = KeyStore.GetInstance(AndroidKeyStore)!;
//         ks.Load(null);
//         return ks;
//     }
//
//     private static ISecretKey GetOrCreateKey()
//     {
//         var ks = GetKeyStore();
//         if (ks.ContainsAlias(KeyAlias))
//         {
//             if (ks.GetKey(KeyAlias, null) is ISecretKey existing)
//                 return existing;
//         }
//
//         var generator = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes!, AndroidKeyStore)!;
//         var builder = new KeyGenParameterSpec.Builder(
//                 KeyAlias,
//                 KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)!
//             .SetKeySize(256)!
//             .SetBlockModes(KeyProperties.BlockModeGcm!)!
//             .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone!)!
//             .SetRandomizedEncryptionRequired(true)!;
//
//         generator.Init(builder.Build());
//         return generator.GenerateKey()!;
//     }
//
//        public bool IsAvailable()
//     {
//         try
//         {
//             if (!OperatingSystem.IsAndroidVersionAtLeast(23))
//                 return false;
//
//             var ctx = Application.Context;
//             if (ctx == null) return false;
//
//             // Полный сквозной тест (шифрование -> SharedPreferences -> расшифровка -> удаление)
//             const string probePkg = "__nativesecrets_probe__";
//             const string probeSvc = "__probe__";
//             const string probeUsr = "__probe__";
//             const string probeVal = "probe_ok";
//
//             SetPassword(probePkg, probeSvc, probeUsr, probeVal);
//             var roundtrip = GetPassword(probePkg, probeSvc, probeUsr);
//             DeletePassword(probePkg, probeSvc, probeUsr);
//
//             return roundtrip == probeVal;
//         }
//         catch
//         {
//             return false;
//         }
//     }
//
//     private static string MakeKey(string package, string service, string user)
//         => Convert.ToBase64String(Encoding.UTF8.GetBytes($"{package}\0{service}\0{user}"));
//
//     public void SetPassword(string package, string service, string user, string password)
//     {
//         var key = GetOrCreateKey();
//         var cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
//         cipher.Init(Javax.Crypto.CipherMode.EncryptMode, key);
//
//         byte[] plain = Encoding.UTF8.GetBytes(password);
//         try
//         {
//             byte[] cipherBytes = cipher.DoFinal(plain)!;
//             byte[] iv = cipher.GetIV()!;
//
//             string payload = $"{Convert.ToBase64String(iv)}:{Convert.ToBase64String(cipherBytes)}";
//
//             var prefs = GetPrefs(Application.Context);
//             using var editor = prefs.Edit()!;
//             editor.PutString(MakeKey(package, service, user), payload);
//             editor.Apply();
//         }
//         finally
//         {
//             CryptographicOperations.ZeroMemory(plain);
//         }
//     }
//
//     public string? GetPassword(string package, string service, string user)
//     {
//         var prefs = GetPrefs(Application.Context);
//         string? stored = prefs.GetString(MakeKey(package, service, user), null);
//         if (string.IsNullOrEmpty(stored)) return null;
//
//         var parts = stored.Split(':');
//         if (parts.Length != 2) return null;
//
//         byte[] iv = Convert.FromBase64String(parts.First());
//         byte[] cipherBytes = Convert.FromBase64String(parts.Last());
//
//         var key = GetOrCreateKey();
//         var cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
//         using var spec = new GCMParameterSpec(GcmTagLengthBits, iv, 0, iv.Length);
//         cipher.Init(Javax.Crypto.CipherMode.DecryptMode, key, spec);
//
//         byte[] plain = cipher.DoFinal(cipherBytes)!;
//         try
//         {
//             return Encoding.UTF8.GetString(plain);
//         }
//         finally
//         {
//             CryptographicOperations.ZeroMemory(plain);
//         }
//     }
//
//     public bool DeletePassword(string package, string service, string user)
//     {
//         var prefs = GetPrefs(Application.Context);
//         string key = MakeKey(package, service, user);
//         if (!prefs.Contains(key)) return false;
//
//         using var editor = prefs.Edit()!;
//         editor.Remove(key);
//         editor.Apply();
//         return true;
//     }
// }
// #endif