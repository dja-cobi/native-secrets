using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NativeSecrets.Abstractions;
using NativeSecrets.Internal;

namespace NativeSecrets.Fallback;

/// <summary>
/// AES-GCM encrypted file store used when no native keychain is available.
/// The encryption key is derived (PBKDF2-SHA256, 200k iterations) from machine/user/device identifiers,
/// so the store is intentionally not portable across machines.
/// </summary>
internal sealed class EncryptedFileFallbackStore : KeychainStoreBase
{
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int SaltSize = 16;
    private const int Iterations = 200_000;

    private readonly string _filePath;
    private readonly byte[] _key;
    private readonly Lock _lock = new();

    /// <summary>Creates a fallback store.</summary>
    /// <param name="directory">Directory for <c>secrets.bin</c>. Defaults to <c>%APPDATA%/NativeSecrets</c>.</param>
    /// <param name="env">Environment info provider; <c>null</c> uses <see cref="DefaultEnvironmentInfo"/>.</param>
    public EncryptedFileFallbackStore(string? directory = null, IEnvironmentInfo? env = null)
    {
        env ??= new DefaultEnvironmentInfo();
        
        var dirPath = directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NativeSecrets");
        Directory.CreateDirectory(dirPath);

        if (!OperatingSystem.IsWindows())
        {
            try
            {
                File.SetUnixFileMode(dirPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            catch
            {
                // ignored
            }
        }
        
        _filePath = Path.Combine(dirPath, "secrets.bin");
        
        var deviceId = env.GetDeviceId();
        var salt = SHA256.HashData(Encoding.UTF8.GetBytes($"{env.MachineName}|{env.UserName}|{deviceId}"))[..SaltSize];
        _key = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes($"{env.MachineName}|{env.UserName}|{deviceId}|NativeSecrets-v1"),
            salt, Iterations, HashAlgorithmName.SHA256, KeySize);
    }

    /// <inheritdoc />
    public override bool IsAvailable(TimeSpan? timeout = null) => true;
    
    /// <inheritdoc />
    public override void SetPassword(string package, string service, string user, string password)
    {
        KeychainGuard.ValidateKey(package, service, user);
        KeychainGuard.ValidatePassword(password);
        
        lock (_lock)
        {
            var file = Load();
            var key = KeyBuilder.BuildNulSeparatedBase64(package, service, user);
            file.Entries.RemoveAll(e => e.K == key);

            var plain = Encoding.UTF8.GetBytes(password);
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var cipher = new byte[plain.Length];
            var tag = new byte[TagSize];
            try
            {
                using var aes = new AesGcm(_key, TagSize);
                aes.Encrypt(nonce, plain, cipher, tag);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plain);
            }

            file.Entries.Add(new VaultEntry
            {
                K = key,
                N = Convert.ToBase64String(nonce),
                C = Convert.ToBase64String(cipher),
                T = Convert.ToBase64String(tag)
            });
            Save(file);
        }
    }

    /// <inheritdoc />
    public override string? GetPassword(string package, string service, string user)
    {
        KeychainGuard.ValidateKey(package, service, user);
        
        lock (_lock)
        {
            var file = Load();
            var key = KeyBuilder.BuildNulSeparatedBase64(package, service, user);
            var entry = file.Entries.Find(e => e.K == key);
            if (entry == null)
                return null;

            byte[]? plain = null;
            
            try
            {
                var nonce = Convert.FromBase64String(entry.N);
                var cipher = Convert.FromBase64String(entry.C);
                var tag = Convert.FromBase64String(entry.T);
                plain = new byte[cipher.Length];
                using var aes = new AesGcm(_key, TagSize);
                aes.Decrypt(nonce, cipher, tag, plain);
                return Encoding.UTF8.GetString(plain);
            }
            catch
            {
                return null;
            }
            finally
            {
                if (plain != null) CryptographicOperations.ZeroMemory(plain);
            }
        }
    }

    /// <inheritdoc />
    public override bool DeletePassword(string package, string service, string user)
    {
        KeychainGuard.ValidateKey(package, service, user);
        
        lock (_lock)
        {
            var file = Load();
            var key = KeyBuilder.BuildNulSeparatedBase64(package, service, user);
            var removed = file.Entries.RemoveAll(e => e.K == key);
            if (removed <= 0) return false;
            Save(file);
            return true;
        }
    }

    /// <inheritdoc />
    protected override void DisposeCore()
    {
        CryptographicOperations.ZeroMemory(_key);
    }

    /// <summary>Loads the secrets; returns an empty one if the file is missing or corrupt.</summary>
    private VaultFile Load()
    {
        if (!File.Exists(_filePath)) return new VaultFile();

        try
        {
            var raw = File.ReadAllBytes(_filePath);
            var file = JsonSerializer.Deserialize(raw, VaultJsonContext.Default.VaultFile) ?? new VaultFile();
            return file.Version == VaultFile.CurrentVersion ? file : new VaultFile();
        }
        catch
        {
            return new VaultFile();
        }
    }

    /// <summary>Atomically writes the secrets (temp file + rename).</summary>
    private void Save(VaultFile file)
    {
        var raw = JsonSerializer.SerializeToUtf8Bytes(file, VaultJsonContext.Default.VaultFile);
        var tmp = _filePath + ".tmp";
        File.WriteAllBytes(tmp, raw);
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch
            {
                // ignored
            }
        }
        File.Move(tmp, _filePath, overwrite: true);
    }
}

/// <summary>Single vault entry.</summary>
public sealed class VaultEntry
{
    /// <summary>Base64 of the identifier (see <see cref="KeyBuilder.BuildNulSeparatedBase64"/>).</summary>
    public string K { get; set; } = "";

    /// <summary>Base64 nonce.</summary>
    public string N { get; set; } = "";

    /// <summary>Base64 ciphertext.</summary>
    public string C { get; set; } = "";

    /// <summary>Base64 GCM tag.</summary>
    public string T { get; set; } = "";
}

/// <summary>Vault file container.</summary>
public sealed class VaultFile
{
    /// <summary>Current format version.</summary>
    public const int CurrentVersion = 1;

    /// <summary>Format version. Used for future migrations.</summary>
    public int Version { get; set; } = CurrentVersion;

    /// <summary>All entries.</summary>
    public List<VaultEntry> Entries { get; set; } = [];
}

// internal sealed class EncryptedFileFallbackStore : IKeychainStore
// {
//     private const int KeySize = 32;
//     private const int NonceSize = 12;
//     private const int TagSize = 16;
//     private const int SaltSize = 16;
//     private const int Iterations = 200_000;
//     private readonly string _dirPath;
//
//     private readonly string _filePath;
//     private readonly byte[] _key;
//     private readonly Lock _lock = new();
//     private readonly byte[] _salt;
//
//     public EncryptedFileFallbackStore()
//     {
//         _dirPath = Path.Combine(
//             Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
//             "SecureVault");
//         Directory.CreateDirectory(_dirPath);
//         if (!OperatingSystem.IsWindows())
//             try
//             {
//                 File.SetUnixFileMode(_dirPath,
//                     UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
//             }
//             catch
//             {
//             }
//
//         _filePath = Path.Combine(_dirPath, "secrets.bin");
//
//         var machine = Environment.MachineName;
//         var user = Environment.UserName;
//         var deviceId = TryGetDeviceId();
//
//         _salt = SHA256.HashData(Encoding.UTF8.GetBytes($"{machine}|{user}|{deviceId}"))[..SaltSize];
//         _key = Rfc2898DeriveBytes.Pbkdf2(
//             Encoding.UTF8.GetBytes($"{machine}|{user}|{deviceId}|SecureVault-v1"),
//             _salt, Iterations, HashAlgorithmName.SHA256, KeySize);
//     }
//
//     public bool IsAvailable()
//     {
//         return true;
//     }
//
//     public void SetPassword(string package, string service, string user, string password)
//     {
//         lock (_lock)
//         {
//             var file = Load();
//             var key = MakeKey(package, service, user);
//             file.Entries.RemoveAll(e => e.K == Convert.ToBase64String(Encoding.UTF8.GetBytes(key)));
//
//             var plain = Encoding.UTF8.GetBytes(password);
//             var nonce = RandomNumberGenerator.GetBytes(NonceSize);
//             var cipher = new byte[plain.Length];
//             var tag = new byte[TagSize];
//             using (var aes = new AesGcm(_key, TagSize))
//             {
//                 aes.Encrypt(nonce, plain, cipher, tag);
//             }
//
//             file.Entries.Add(new VaultEntry
//             {
//                 K = Convert.ToBase64String(Encoding.UTF8.GetBytes(key)),
//                 N = Convert.ToBase64String(nonce),
//                 C = Convert.ToBase64String(cipher),
//                 T = Convert.ToBase64String(tag)
//             });
//             Save(file);
//         }
//     }
//
//     public string? GetPassword(string package, string service, string user)
//     {
//         lock (_lock)
//         {
//             var file = Load();
//             var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(MakeKey(package, service, user)));
//             var entry = file.Entries.Find(e => e.K == key);
//             if (entry == null) return null;
//
//             try
//             {
//                 var nonce = Convert.FromBase64String(entry.N);
//                 var cipher = Convert.FromBase64String(entry.C);
//                 var tag = Convert.FromBase64String(entry.T);
//                 var plain = new byte[cipher.Length];
//                 using var aes = new AesGcm(_key, TagSize);
//                 aes.Decrypt(nonce, cipher, tag, plain);
//                 return Encoding.UTF8.GetString(plain);
//             }
//             catch
//             {
//                 return null;
//             }
//         }
//     }
//
//     public bool DeletePassword(string package, string service, string user)
//     {
//         lock (_lock)
//         {
//             var file = Load();
//             var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(MakeKey(package, service, user)));
//             var removed = file.Entries.RemoveAll(e => e.K == key);
//             if (removed > 0)
//             {
//                 Save(file);
//                 return true;
//             }
//
//             return false;
//         }
//     }
//
//     private static string TryGetDeviceId()
//     {
//         try
//         {
//             if (OperatingSystem.IsLinux())
//             {
//                 const string p = "/etc/machine-id";
//                 if (File.Exists(p)) return File.ReadAllText(p).Trim();
//             }
//             else if (OperatingSystem.IsMacOS())
//             {
//                 // Без рефлексии. Читаем через /usr/sbin/ioreg нельзя — это процесс.
//                 // Используем псевдо-идентификатор из окружения.
//                 return Environment.GetEnvironmentVariable("IOPlatformUUID") ?? "mac";
//             }
//             else if (OperatingSystem.IsWindows())
//             {
//                 // Без рефлексии MachineGuid — только через P/Invoke к реестру,
//                 // что запрещено требованиями (нет рефлексии и системных вызовов вне спецификации).
//                 return Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "win";
//             }
//         }
//         catch
//         {
//         }
//
//         return "unknown";
//     }
//
//     private static string MakeKey(string package, string service, string user)
//     {
//         return $"{package}\0{service}\0{user}";
//     }
//
//     private VaultFile Load()
//     {
//         if (!File.Exists(_filePath)) return new VaultFile();
//         try
//         {
//             var raw = File.ReadAllBytes(_filePath);
//             var json = Encoding.UTF8.GetString(raw);
//             return JsonSerializer.Deserialize(raw, Fallback.VaultJsonContext.Default.VaultFile) ?? new VaultFile();
//         }
//         catch
//         {
//             return new VaultFile();
//         }
//     }
//
//     private void Save(VaultFile file)
//     {
//         // var json = JsonSerializer.Serialize(file);
//         // var raw = Encoding.UTF8.GetBytes(json);
//         var raw = JsonSerializer.SerializeToUtf8Bytes(file, Fallback.VaultJsonContext.Default.VaultFile);
//         File.WriteAllBytes(_filePath, raw);
//         if (!OperatingSystem.IsWindows())
//         {
//             try
//             {
//                 File.SetUnixFileMode(_filePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
//             }
//             catch
//             {
//             }
//         }
//     }
//
//     public sealed class VaultEntry
//     {
//         public string K { get; set; } = "";
//         public string N { get; set; } = "";
//         public string C { get; set; } = "";
//         public string T { get; set; } = "";
//     }
//
//     public sealed class VaultFile
//     {
//         public List<VaultEntry> Entries { get; set; } = new();
//     }
//     
// }