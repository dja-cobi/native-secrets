#if ANDROID || __ANDROID__
using System.Security.Cryptography;
using System.Text;
using Android.App;
using Android.Content;
using Android.Security.Keystore;
using Android.Util;
using Java.Security;
using Javax.Crypto;
using NativeSecrets.Abstractions;
using NativeSecrets.Internal;

namespace NativeSecrets.Platforms;

internal sealed class AndroidKeychain : KeychainStoreBase
{
    private const string DefaultKeyAlias = "NativeSecrets.WrappingKey";
    private const string ActiveAliasPrefKey = "__nativesecrets_active_alias__";
    private const string WrappedDekPrefKey = "__nativesecrets_wrapped_dek__";
    private const string PrefsName = "nativesecrets_vault";
    private const string AndroidKeyStore = "AndroidKeyStore";
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private static ISharedPreferences GetPrefs(Context ctx)
        => ctx.GetSharedPreferences(PrefsName, FileCreationMode.Private)!;

    private static string GetCurrentAlias(Context ctx)
        => GetPrefs(ctx).GetString(ActiveAliasPrefKey, DefaultKeyAlias) ?? DefaultKeyAlias;

    private static KeyStore GetKeyStore()
    {
        var ks = KeyStore.GetInstance(AndroidKeyStore)!;
        ks.Load(null);
        return ks;
    }

    private static KeyPair GetOrCreateWrappingKeyPair(string alias)
    {
        var ks = GetKeyStore();
        if (ks.ContainsAlias(alias))
        {
            var entry = ks.GetEntry(alias, null);
            if (entry is KeyStore.PrivateKeyEntry privEntry && privEntry.Certificate?.PublicKey != null)
            {
                return new KeyPair(privEntry.Certificate.PublicKey, privEntry.PrivateKey);
            }
        }

        var generator = KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmRsa!, AndroidKeyStore)!;
        var builder = new KeyGenParameterSpec.Builder(
                alias,
                KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)!
            .SetKeySize(2048)!
            .SetEncryptionPaddings(KeyProperties.EncryptionPaddingRsaPkcs1!)!;

        generator.Initialize(builder.Build());
        return generator.GenerateKeyPair()!;
    }

    private static byte[] GetOrCreateDataKey()
    {
        var ctx = Application.Context!;
        var prefs = GetPrefs(ctx);
        var alias = GetCurrentAlias(ctx);
        var keyPair = GetOrCreateWrappingKeyPair(alias);

        var wrappedB64 = prefs.GetString(WrappedDekPrefKey, null);
        if (!string.IsNullOrEmpty(wrappedB64))
        {
            var wrapped = Convert.FromBase64String(wrappedB64);
            var decryptCipher = Cipher.GetInstance("RSA/ECB/PKCS1Padding")!;
            decryptCipher.Init(Javax.Crypto.CipherMode.DecryptMode, keyPair.Private);
            return decryptCipher.DoFinal(wrapped)!;
        }

        var dek = RandomNumberGenerator.GetBytes(32);
        var encryptCipher = Cipher.GetInstance("RSA/ECB/PKCS1Padding")!;
        encryptCipher.Init(Javax.Crypto.CipherMode.EncryptMode, keyPair.Public);
        var newWrapped = encryptCipher.DoFinal(dek)!;

        using var editor = prefs.Edit()!;
        editor.PutString(WrappedDekPrefKey, Convert.ToBase64String(newWrapped));
        editor.Commit();

        return dek;
    }

    private static void ResetVault()
    {
        var ctx = Application.Context;
        if (ctx == null) return;

        var oldAlias = GetCurrentAlias(ctx);
        try
        {
            var ks = GetKeyStore();
            if (ks.ContainsAlias(oldAlias))
                ks.DeleteEntry(oldAlias);
        }
        catch { }

        try
        {
            var newAlias = $"{DefaultKeyAlias}.{Guid.NewGuid():N}";
            using var editor = GetPrefs(ctx).Edit()!;
            editor.Clear();
            editor.PutString(ActiveAliasPrefKey, newAlias);
            editor.Commit();
        }
        catch { }
    }

    public override bool IsAvailable(TimeSpan? timeout = null)
    {
        try
        {
            if (!OperatingSystem.IsAndroidVersionAtLeast(23)) return false;
            if (Application.Context == null) return false;

            if (RunProbe()) return true;

            ResetVault();
            return RunProbe();
        }
        catch
        {
            return false;
        }
    }

    private bool RunProbe()
    {
        const string probePkg = "__nativesecrets_probe__";
        const string probeSvc = "__probe__";
        const string probeUsr = "__probe__";
        const string probeVal = "probe_ok";

        try
        {
            SetPassword(probePkg, probeSvc, probeUsr, probeVal);
            return GetPassword(probePkg, probeSvc, probeUsr) == probeVal;
        }
        catch (Exception ex)
        {
            Log.Error("NativeSecretsProbe", ex.ToString());
            return false;
        }
        finally
        {
            try { DeletePassword(probePkg, probeSvc, probeUsr); } catch { }
        }
    }

    public override void SetPassword(string package, string service, string user, string password)
    {
        KeychainGuard.ValidateKey(package, service, user);
        KeychainGuard.ValidatePassword(password);

        var dek = GetOrCreateDataKey();
        var plain = Encoding.UTF8.GetBytes(password);
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var cipherBytes = new byte[plain.Length];
            var tag = new byte[TagSize];

            using var aes = new AesGcm(dek, TagSize);
            aes.Encrypt(nonce, plain, cipherBytes, tag);

            var payload = $"{Convert.ToBase64String(nonce)}:{Convert.ToBase64String(tag)}:{Convert.ToBase64String(cipherBytes)}";

            var prefs = GetPrefs(Application.Context);
            using var editor = prefs.Edit()!;
            editor.PutString(KeyBuilder.BuildNulSeparatedBase64(package, service, user), payload);
            editor.Commit();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public override string? GetPassword(string package, string service, string user)
    {
        KeychainGuard.ValidateKey(package, service, user);

        var prefs = GetPrefs(Application.Context);
        var stored = prefs.GetString(KeyBuilder.BuildNulSeparatedBase64(package, service, user), null);
        if (string.IsNullOrEmpty(stored)) return null;

        var parts = stored.Split(':');
        if (parts.Length != 3) return null;

        var nonce = Convert.FromBase64String(parts.ElementAt(0));
        var tag = Convert.FromBase64String(parts.ElementAt(1));
        var cipherBytes = Convert.FromBase64String(parts.ElementAt(2));

        var dek = GetOrCreateDataKey();
        var plain = new byte[cipherBytes.Length];
        try
        {
            using var aes = new AesGcm(dek, TagSize);
            aes.Decrypt(nonce, cipherBytes, tag, plain);
            return Encoding.UTF8.GetString(plain);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public override bool DeletePassword(string package, string service, string user)
    {
        KeychainGuard.ValidateKey(package, service, user);

        var prefs = GetPrefs(Application.Context);
        var key = KeyBuilder.BuildNulSeparatedBase64(package, service, user);
        if (!prefs.Contains(key)) return false;

        using var editor = prefs.Edit()!;
        editor.Remove(key);
        editor.Commit();
        return true;
    }
}
#endif








// #if ANDROID || __ANDROID__
// using System.Security.Cryptography;
// using System.Text;
// using Android.App;
// using Android.Content;
// using Android.Security.Keystore;
// using Java.Security;
// using Javax.Crypto;
// using Javax.Crypto.Spec;
// using NativeSecrets.Abstractions;
// using NativeSecrets.Internal;
//
// namespace NativeSecrets.Platforms;
//
// /// <summary>Android Keystore-backed store (AES-256-GCM, encrypted payload in SharedPreferences).</summary>
// internal sealed class AndroidKeychain : KeychainStoreBase
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
//     /// <inheritdoc />
//     public override bool IsAvailable(TimeSpan? timeout = null)
//     {
//         try
//         {
//             if (!OperatingSystem.IsAndroidVersionAtLeast(23)) return false;
//             if (Application.Context == null) return false;
//
//             const string probePkg = "__nativesecrets_probe__";
//             const string probeSvc = "__probe__";
//             const string probeUsr = "__probe__";
//             const string probeVal = "probe_ok";
//
//             try
//             {
//                 SetPassword(probePkg, probeSvc, probeUsr, probeVal);
//                 return GetPassword(probePkg, probeSvc, probeUsr) == probeVal;
//             }
//             finally
//             {
//                 try { DeletePassword(probePkg, probeSvc, probeUsr); } catch { }
//             }
//         }
// catch (Exception ex)
// {
//     Android.Util.Log.Error("NativeSecretsProbe", ex.ToString());
//     return false;
// }
//
//         // catch
//         // {
//         //     return false;
//         // }
//     }
//
//     /// <inheritdoc />
//     public override void SetPassword(string package, string service, string user, string password)
//     {
//         KeychainGuard.ValidateKey(package, service, user);
//         KeychainGuard.ValidatePassword(password);
//
//         var key = GetOrCreateKey();
//         var cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
//         cipher.Init(Javax.Crypto.CipherMode.EncryptMode, key);
//
//         var plain = Encoding.UTF8.GetBytes(password);
//         try
//         {
//             var cipherBytes = cipher.DoFinal(plain)!;
//             var iv = cipher.GetIV()!;
//             var payload = $"{Convert.ToBase64String(iv)}:{Convert.ToBase64String(cipherBytes)}";
//
//             var prefs = GetPrefs(Application.Context);
//             using var editor = prefs.Edit()!;
//             editor.PutString(KeyBuilder.BuildNulSeparatedBase64(package, service, user), payload);
//             editor.Apply();
//         }
//         finally
//         {
//             CryptographicOperations.ZeroMemory(plain);
//         }
//     }
//
//     /// <inheritdoc />
//     public override string? GetPassword(string package, string service, string user)
//     {
//         KeychainGuard.ValidateKey(package, service, user);
//
//         var prefs = GetPrefs(Application.Context);
//         var stored = prefs.GetString(KeyBuilder.BuildNulSeparatedBase64(package, service, user), null);
//         if (string.IsNullOrEmpty(stored)) return null;
//
//         var parts = stored.Split(':');
//         if (parts.Length != 2) return null;
//
//         var iv = Convert.FromBase64String(parts[0]);
//         var cipherBytes = Convert.FromBase64String(parts[1]);
//
//         var key = GetOrCreateKey();
//         var cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
//         using var spec = new GCMParameterSpec(GcmTagLengthBits, iv, 0, iv.Length);
//         cipher.Init(Javax.Crypto.CipherMode.DecryptMode, key, spec);
//
//         var plain = cipher.DoFinal(cipherBytes)!;
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
//     /// <inheritdoc />
//     public override bool DeletePassword(string package, string service, string user)
//     {
//         KeychainGuard.ValidateKey(package, service, user);
//
//         var prefs = GetPrefs(Application.Context);
//         var key = KeyBuilder.BuildNulSeparatedBase64(package, service, user);
//         if (!prefs.Contains(key)) return false;
//
//         using var editor = prefs.Edit()!;
//         editor.Remove(key);
//         editor.Apply();
//         return true;
//     }
// }
// #endif


// WOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOORRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRKKKKKK

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
// using NativeSecrets.Abstractions;
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
//     public bool IsAvailable()
//     {
//         try
//         {
//             if (!OperatingSystem.IsAndroidVersionAtLeast(23))
//                 return false;
//
//             var ctx = Application.Context;
//             if (ctx == null) return false;
//
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
//             editor.PutString(KeyBuilder.BuildNulSeparatedBase64(package, service, user), payload);
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
//         string? stored = prefs.GetString(KeyBuilder.BuildNulSeparatedBase64(package, service, user), null);
//         if (string.IsNullOrEmpty(stored)) return null;
//
//         var parts = stored.Split(':');
//         if (parts.Length != 2) return null;
//
//         byte[] iv = Convert.FromBase64String(parts[0]);
//         byte[] cipherBytes = Convert.FromBase64String(parts[1]);
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
//         string key = KeyBuilder.BuildNulSeparatedBase64(package, service, user);
//         if (!prefs.Contains(key)) return false;
//
//         using var editor = prefs.Edit()!;
//         editor.Remove(key);
//         editor.Apply();
//         return true;
//     }
// }
// #endif

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