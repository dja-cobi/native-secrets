using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NativeSecrets;

internal sealed class EncryptedFileFallbackStore : IKeychainStore
{
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int SaltSize = 16;
    private const int Iterations = 200_000;
    private readonly string _dirPath;

    private readonly string _filePath;
    private readonly byte[] _key;
    private readonly Lock _lock = new();
    private readonly byte[] _salt;

    public EncryptedFileFallbackStore()
    {
        _dirPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "SecureVault");
        Directory.CreateDirectory(_dirPath);
        if (!OperatingSystem.IsWindows())
            try
            {
                File.SetUnixFileMode(_dirPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            catch
            {
            }

        _filePath = Path.Combine(_dirPath, "secrets.bin");

        var machine = Environment.MachineName;
        var user = Environment.UserName;
        var deviceId = TryGetDeviceId();

        _salt = SHA256.HashData(Encoding.UTF8.GetBytes($"{machine}|{user}|{deviceId}"))[..SaltSize];
        _key = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes($"{machine}|{user}|{deviceId}|SecureVault-v1"),
            _salt, Iterations, HashAlgorithmName.SHA256, KeySize);
    }

    public bool IsAvailable()
    {
        return true;
    }

    public void SetPassword(string package, string service, string user, string password)
    {
        lock (_lock)
        {
            var file = Load();
            var key = MakeKey(package, service, user);
            file.Entries.RemoveAll(e => e.K == Convert.ToBase64String(Encoding.UTF8.GetBytes(key)));

            var plain = Encoding.UTF8.GetBytes(password);
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var cipher = new byte[plain.Length];
            var tag = new byte[TagSize];
            using (var aes = new AesGcm(_key, TagSize))
            {
                aes.Encrypt(nonce, plain, cipher, tag);
            }

            file.Entries.Add(new VaultEntry
            {
                K = Convert.ToBase64String(Encoding.UTF8.GetBytes(key)),
                N = Convert.ToBase64String(nonce),
                C = Convert.ToBase64String(cipher),
                T = Convert.ToBase64String(tag)
            });
            Save(file);
        }
    }

    public string? GetPassword(string package, string service, string user)
    {
        lock (_lock)
        {
            var file = Load();
            var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(MakeKey(package, service, user)));
            var entry = file.Entries.Find(e => e.K == key);
            if (entry == null) return null;

            try
            {
                var nonce = Convert.FromBase64String(entry.N);
                var cipher = Convert.FromBase64String(entry.C);
                var tag = Convert.FromBase64String(entry.T);
                var plain = new byte[cipher.Length];
                using var aes = new AesGcm(_key, TagSize);
                aes.Decrypt(nonce, cipher, tag, plain);
                return Encoding.UTF8.GetString(plain);
            }
            catch
            {
                return null;
            }
        }
    }

    public bool DeletePassword(string package, string service, string user)
    {
        lock (_lock)
        {
            var file = Load();
            var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(MakeKey(package, service, user)));
            var removed = file.Entries.RemoveAll(e => e.K == key);
            if (removed > 0)
            {
                Save(file);
                return true;
            }

            return false;
        }
    }

    private static string TryGetDeviceId()
    {
        try
        {
            if (OperatingSystem.IsLinux())
            {
                const string p = "/etc/machine-id";
                if (File.Exists(p)) return File.ReadAllText(p).Trim();
            }
            else if (OperatingSystem.IsMacOS())
            {
                // Без рефлексии. Читаем через /usr/sbin/ioreg нельзя — это процесс.
                // Используем псевдо-идентификатор из окружения.
                return Environment.GetEnvironmentVariable("IOPlatformUUID") ?? "mac";
            }
            else if (OperatingSystem.IsWindows())
            {
                // Без рефлексии MachineGuid — только через P/Invoke к реестру,
                // что запрещено требованиями (нет рефлексии и системных вызовов вне спецификации).
                return Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "win";
            }
        }
        catch
        {
        }

        return "unknown";
    }

    private static string MakeKey(string package, string service, string user)
    {
        return $"{package}\0{service}\0{user}";
    }

    private VaultFile Load()
    {
        if (!File.Exists(_filePath)) return new VaultFile();
        try
        {
            var raw = File.ReadAllBytes(_filePath);
            var json = Encoding.UTF8.GetString(raw);
            return JsonSerializer.Deserialize(raw, VaultJsonContext.Default.VaultFile) ?? new VaultFile();
        }
        catch
        {
            return new VaultFile();
        }
    }

    private void Save(VaultFile file)
    {
        // var json = JsonSerializer.Serialize(file);
        // var raw = Encoding.UTF8.GetBytes(json);
        var raw = JsonSerializer.SerializeToUtf8Bytes(file, VaultJsonContext.Default.VaultFile);
        File.WriteAllBytes(_filePath, raw);
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                File.SetUnixFileMode(_filePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch
            {
            }
        }
    }

    public sealed class VaultEntry
    {
        public string K { get; set; } = "";
        public string N { get; set; } = "";
        public string C { get; set; } = "";
        public string T { get; set; } = "";
    }

    public sealed class VaultFile
    {
        public List<VaultEntry> Entries { get; set; } = new();
    }
    
}

[JsonSerializable(typeof(EncryptedFileFallbackStore.VaultFile))]
internal partial class VaultJsonContext : JsonSerializerContext { }

