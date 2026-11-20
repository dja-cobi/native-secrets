# NativeSecrets

[![NuGet](https://shields.io)](https://nuget.org)
[![License: MIT](https://shields.io)](LICENSE)

**English** | [Русский](README.ru.md)

A cross-platform .NET library for storing secrets (tokens, passwords, API keys) in native OS credential stores with automatic fallback to an encrypted local file.

Suitable for any **.NET 8 / 9 / 10 / 11** application: CLI tools, background services, ASP.NET Core, Avalonia, .NET MAUI, WPF, and WinForms. Built with zero reflection (`[LibraryImport]`, Source-Generated JSON) and full **Native AOT** and **Trimming** compatibility.

---

## Installation

```bash
dotnet add package NativeSecrets
```

---

## Supported Platforms

On first access, `NativeSecrets` probes the native OS store (`IsAvailable`). If the system keyring is unavailable (e.g., inside a Docker container, headless server, or CI environment without D-Bus), it transparently falls back to a local encrypted file store.

| Platform | Min. Version | Native Backend | Implementation |
| :--- | :--- | :--- | :--- |
| **Windows** | Windows 10+ | Windows Credential Manager | `advapi32.dll` (`CredWriteW` / `CredReadW` / `CredDeleteW`, `CRED_TYPE_GENERIC`) |
| **macOS** | macOS 12+ | Apple Keychain | `Security.framework` + `CoreFoundation` (`kSecClassGenericPassword`) |
| **iOS / Mac Catalyst** | iOS 15.0+ (.NET 10/11) | iOS Keychain | `Security` (`SecKind.GenericPassword`, `SecAccessible.AfterFirstUnlock`) |
| **Linux** | Any with `libsecret` | Secret Service API (D-Bus) | `libsecret-1.so.0` (GNOME Keyring / KWallet) |
| **Android** | Android 6.0 / API 23+ (.NET 10)<br>Android 7.0 / API 24+ (.NET 11) | Android Keystore | RSA-2048 wrapping key in `AndroidKeyStore` + AES-256-GCM encrypted payload in private `SharedPreferences` |
| **Fallback (all OS)** | .NET 8 / 9 / 10 / 11 | Encrypted file `secrets.bin` | AES-256-GCM; key derived via PBKDF2-SHA256 (200,000 iterations) bound to machine, user, and device ID |

---

## Usage

### 1. Quick Start (Without DI)

For most scenarios, use the thread-safe `KeychainFactory.Instance` singleton. It lazily initializes the provider on first call.

```csharp
using NativeSecrets.Core;

const string package = "com.example.MyApp";
const string service = "ApiTokens";
const string user = "default";

// Store a secret
await KeychainFactory.Instance.SetPasswordAsync(package, service, user, "secret-token-123");

// Retrieve a secret (returns null if not found)
string? token = await KeychainFactory.Instance.GetPasswordAsync(package, service, user);

// Delete a secret (returns true if the entry existed)
bool deleted = await KeychainFactory.Instance.DeletePasswordAsync(package, service, user);

// Check whether the encrypted file fallback is active
bool isFallback = KeychainFactory.IsUsingFallback;
```

> Synchronous overloads (`SetPassword`, `GetPassword`, `DeletePassword`) are also available. Prefer `*Async` methods in UI contexts.

---

### 2. Dependency Injection

Register `IKeychainStore` as a singleton using `AddNativeSecrets`:

```csharp
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NativeSecrets.Abstractions;
using NativeSecrets.Core;

using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());

var services = new ServiceCollection();
services.AddNativeSecrets(options =>
{
    options.AvailabilityTimeout = TimeSpan.FromSeconds(3);
    options.Logger = loggerFactory.CreateLogger("NativeSecrets");
});

using var serviceProvider = services.BuildServiceProvider();

// Resolve IKeychainStore from the container
var store = serviceProvider.GetRequiredService<IKeychainStore>();
await store.SetPasswordAsync("com.example.MyApp", "Database", "admin", "P@ssw0rd!");

// Optional: check whether fallback is being used
if (store is KeychainStoreProvider { IsUsingFallback: true })
{
    Console.WriteLine("Using encrypted file fallback store.");
}
```

Injecting into your application services:

```csharp
using NativeSecrets.Abstractions;

public sealed class TokenStorage(IKeychainStore keychain)
{
    public Task SaveAsync(string userId, string token, CancellationToken ct = default)
        => keychain.SetPasswordAsync("com.example.MyApp", "Auth", userId, token, ct);

    public Task<string?> LoadAsync(string userId, CancellationToken ct = default)
        => keychain.GetPasswordAsync("com.example.MyApp", "Auth", userId, ct);

    public Task<bool> RemoveAsync(string userId, CancellationToken ct = default)
        => keychain.DeletePasswordAsync("com.example.MyApp", "Auth", userId, ct);
}
```

---

### 3. Custom Configuration Without DI (`CreateProvider`)

To customize the fallback directory, force the file fallback (e.g., in CI or tests), or pass a logger without DI:

```csharp
using Microsoft.Extensions.Logging;
using NativeSecrets.Abstractions;
using NativeSecrets.Core;

using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());

var options = new KeychainOptions
{
    ForceFallback = true,
    FallbackDirectory = Path.Combine(AppContext.BaseDirectory, "vault"),
    AvailabilityTimeout = TimeSpan.FromSeconds(5),
    Logger = loggerFactory.CreateLogger("NativeSecrets")
};

using KeychainStoreProvider provider = KeychainFactory.CreateProvider(options);
provider.SetPassword("com.example.Service", "Broker", "", "amqps://...");
```

> **Performance note:** Initializing `EncryptedFileFallbackStore` runs 200,000 iterations of PBKDF2-SHA256. Create the provider once and cache it for the lifetime of your application.

---

## `KeychainOptions` Reference

| Property | Default | Description |
| :--- | :--- | :--- |
| `ForceFallback` | `false` | Bypasses native OS stores and immediately uses the encrypted file fallback. |
| `FallbackDirectory` | `%APPDATA%/NativeSecrets` | Directory where `secrets.bin` is stored. |
| `FallbackStore` | `null` | Custom `IKeychainStore` fallback implementation (useful for unit testing). |
| `Logger` | `NullLogger.Instance` | An `Microsoft.Extensions.Logging.ILogger` instance. |
| `AvailabilityTimeout` | `5 seconds` | Timeout for the native store availability probe (`IsAvailable`). |

---

## Validation Rules

* **`package`** — Required non-empty, non-whitespace string (unique app identifier, e.g., `com.company.App`).
* **`service`** — Required non-empty, non-whitespace string (logical secret group, e.g., `GitHub`, `Stripe`).
* **`user`** — Must not be `null`; empty string `""` is allowed for app-wide secrets.
* **`password`** — Must not be `null`; empty string `""` is allowed.

Invalid arguments throw `ArgumentException` or `ArgumentNullException`.

---

## Platform Notes & Security

* **Linux:** Requires `libsecret-1` (`libsecret-1-0` on Debian/Ubuntu, `libsecret` on Fedora/Arch) and a running Secret Service daemon (`gnome-keyring-daemon` or equivalent). In headless/D-Bus-less environments, `EncryptedFileFallbackStore` is selected automatically.
* **Non-portable fallback file:** The `secrets.bin` encryption key is derived from the machine name, username, and OS device identifier (`/etc/machine-id` on Linux, `IOPlatformUUID` on macOS, `MachineGuid` registry value on Windows). The vault file cannot be decrypted on a different machine or user account.
* **Memory & file hardening:** Plaintext password buffers are zeroed in memory via `CryptographicOperations.ZeroMemory`. On Unix systems, the fallback directory and vault file permissions are restricted to `0700` and `0600`, and writes are performed atomically via temp file + rename.

---

## License

[MIT](LICENSE)
