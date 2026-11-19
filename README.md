# NativeSecrets

Store secrets securely on every platform with one API. Native keychain on Windows, macOS, Linux, Android and iOS — with an encrypted file fallback when no native store is available.

---

## Why

Every platform has its own secure storage:

- **Windows** → Credential Manager
- **macOS / iOS** → Keychain
- **Linux** → libsecret (GNOME Keyring, KWallet, KeePassXC, …)
- **Android** → Keystore

`NativeSecrets` gives you a single `IKeychainStore` interface that works everywhere — and automatically falls back to an AES-256-GCM encrypted file if the native store is unavailable (headless Linux, CI, locked keychain).

---

## Install

```bash
dotnet add package NativeSecrets
```

---

## 60-second example

```csharp
using NativeSecrets.Core;

var store = KeychainFactory.Instance;

// Save
store.SetPassword("com.example.MyApp", "ApiKeys", "alice", "sk-1234567890");

// Read
string? apiKey = store.GetPassword("com.example.MyApp", "ApiKeys", "alice");

// Delete
store.DeletePassword("com.example.MyApp", "ApiKeys", "alice");
```

That's it. On Windows this writes to Credential Manager. On macOS/iOS — to Keychain. On Linux — to your keyring. On Android — to Keystore. If none of those is available, it writes to an encrypted file in `%APPDATA%/SecureVault`.

---

## The three parameters

Every call takes the same triple:

| Parameter | What it is | Example |
|---|---|---|
| `package` | Your application identifier (reverse-DNS works well). | `com.example.MyApp` |
| `service` | A group of secrets — one per feature/area. | `ApiKeys`, `Database`, `OAuth` |
| `user` | Which account this secret belongs to. Empty string if single-user. | `alice`, `bob`, `""` |

The triple `(package, service, user)` is the unique key. Think of it as `package → service → user → secret`.

```
com.example.MyApp / ApiKeys  / alice → "sk-abc..."
com.example.MyApp / ApiKeys  / bob   → "sk-def..."
com.example.MyApp / Database / alice → "Server=...;Password=..."
```

---

## Platform support

| Platform | Backing store | Requirements |
|---|---|---|
| **Windows** | Credential Manager | Windows 7+ |
| **macOS** | Keychain | 10.10+ |
| **Linux** | libsecret / Secret Service | `libsecret-1-0` + keyring daemon |
| **Android** | Keystore + SharedPreferences | API 23+ (Android 6.0) |
| **iOS** | Keychain | iOS 9+ |
| **Mac Catalyst** | Keychain | 13.0+ |
| **Fallback** | AES-256-GCM file | Any .NET 9 TFM |

No extra setup needed on any platform — just add the NuGet package.

---

## Common scenarios

### 1. Desktop app (WPF / WinForms / Avalonia) — remember a login token

```csharp
using NativeSecrets.Abstractions;
using NativeSecrets.Core;

public sealed class TokenStore
{
    private const string Package = "com.example.DesktopApp";
    private const string Service = "Auth";

    private readonly IKeychainStore _keychain;

    public TokenStore(IKeychainStore keychain) => _keychain = keychain;

    public void SaveToken(string username, string token)
        => _keychain.SetPassword(Package, Service, username, token);

    public string? LoadToken(string username)
        => _keychain.GetPassword(Package, Service, username);

    public void ForgetToken(string username)
        => _keychain.DeletePassword(Package, Service, username);
}
```

Register once at startup:

```csharp
var services = new ServiceCollection();
services.AddNativeSecrets();
services.AddSingleton<TokenStore>();

var provider = services.BuildServiceProvider();
var tokens = provider.GetRequiredService<TokenStore>();

tokens.SaveToken("alice", "eyJhbGciOi...");
```

> **UI tip:** on the UI thread prefer the async overloads (`SetPasswordAsync`, `GetPasswordAsync`). Native stores can take tens of milliseconds, which is enough to drop frames.

---

### 2. MAUI app (Android / iOS / Windows / macOS) — login screen

```csharp
using NativeSecrets.Abstractions;

public partial class LoginPage : ContentPage
{
    private readonly IKeychainStore _keychain;
    private const string Package = "com.example.MauiApp";

    public LoginPage(IKeychainStore keychain)
    {
        InitializeComponent();
        _keychain = keychain;
    }

    private async void OnLoginClicked(object sender, EventArgs e)
    {
        var username = UsernameEntry.Text!;
        var password = PasswordEntry.Text!;

        var token = await AuthenticateAsync(username, password);

        // Persist for next launch
        await _keychain.SetPasswordAsync(Package, "Auth", username, token);

        await Navigation.PushAsync(new HomePage());
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();

        // Try a silent login
        var saved = await _keychain.GetPasswordAsync(Package, "Auth", "last-user");
        if (saved is not null)
            await Navigation.PushAsync(new HomePage());
    }
}
```

`MauiProgram.cs`:

```csharp
builder.Services.AddNativeSecrets(o =>
    o.AvailabilityTimeout = TimeSpan.FromSeconds(2)); // don't block startup too long
```

---

### 3. ASP.NET Core / Worker Service — connection string

```csharp
// Program.cs
builder.Services.AddNativeSecrets(o =>
{
    o.Logger = builder.Logging.CreateLogger("NativeSecrets");
    // On a server without a keyring, point the fallback somewhere writable:
    o.FallbackDirectory = "/var/lib/myapp/vault";
});

// Somewhere in your code
public sealed class DbConnectionProvider(IKeychainStore keychain)
{
    private const string Package = "com.example.Api";
    private const string Service = "Database";
    private const string User = "primary";

    public async Task<string?> GetConnectionStringAsync(CancellationToken ct)
        => await keychain.GetPasswordAsync(Package, Service, User, ct);
}
```

Store the connection string once (e.g. via a setup CLI or a one-off admin endpoint):

```csharp
await keychain.SetPasswordAsync(
    "com.example.Api", "Database", "primary",
    "Server=db;Database=app;User Id=app;Password=...;",
    ct);
```

---

### 4. CLI tool — store a GitHub token

```csharp
using NativeSecrets.Core;

var store = KeychainFactory.Instance;
const string Package = "com.example.MyCli";

if (args[0] == "login")
{
    Console.Write("GitHub token: ");
    var token = Console.ReadLine()!;
    store.SetPassword(Package, "GitHub", "default", token);
    Console.WriteLine("Saved.");
}
else if (args[0] == "whoami")
{
    var token = store.GetPassword(Package, "GitHub", "default");
    Console.WriteLine(token is null ? "Not logged in." : $"Token: {token[..8]}…");
}
```

Works identically on Windows, macOS and Linux.

---

### 5. Multi-account — one secret per user

```csharp
// Store per-account refresh tokens
await keychain.SetPasswordAsync("com.example.MyApp", "RefreshToken", "alice@example.com", aliceToken);
await keychain.SetPasswordAsync("com.example.MyApp", "RefreshToken", "bob@example.com",   bobToken);

// Switch accounts
await keychain.SetPasswordAsync("com.example.MyApp", "Auth", "active-account", "alice@example.com");

// Read the active account
var active = await keychain.GetPasswordAsync("com.example.MyApp", "Auth", "active-account");
var token  = active is null ? null : await keychain.GetPasswordAsync("com.example.MyApp", "RefreshToken", active);
```

---

### 6. Headless Linux / Docker / CI — use the fallback on purpose

On servers without a keyring daemon, the native store is unavailable and the fallback is selected automatically. If you want to be explicit:

```csharp
var store = KeychainFactory.CreateProvider(new KeychainOptions
{
    ForceFallback = true,
    FallbackDirectory = "/var/lib/myapp/vault"
});

await store.SetPasswordAsync("com.example.Service", "Db", "app", connectionString);
```

> The fallback encrypts with a key derived from machine/user/device identifiers. **It does not move between machines.** Back up accordingly.

---

## Checking which store is active

```csharp
var store = KeychainFactory.Instance;

if (KeychainFactory.IsUsingFallback)
    logger.LogWarning("Native keychain unavailable — using encrypted file fallback.");

if (!store.IsAvailable())
    logger.LogError("No secret storage available at all.");
```

Useful for diagnostics, telemetry, or showing a warning in Settings → Privacy.

---

## When to use async

The synchronous API is convenient for CLI tools and one-off calls. In anything with a UI or a server request path, prefer async:

```csharp
// Don't block the UI thread
var token = await keychain.GetPasswordAsync("com.example.MyApp", "Auth", "alice", ct);
```

Every method has an async twin that accepts a `CancellationToken`.

---

## Configuration

### `KeychainOptions`

| Property | Type | Default | Description |
|---|---|---|---|
| `ForceFallback` | `bool` | `false` | Skip native stores entirely. |
| `FallbackDirectory` | `string?` | `%APPDATA%/SecureVault` | Directory for the fallback file. |
| `FallbackStore` | `IKeychainStore?` | `null` | Custom fallback implementation (e.g. for tests). |
| `Logger` | `ILogger?` | `NullLogger` | Logger for diagnostics. |
| `AvailabilityTimeout` | `TimeSpan` | `5s` | Timeout for the native availability probe. |

### `KeychainFactory`

| Member | Description |
|---|---|
| `Instance` | Lazily-created shared `IKeychainStore`. |
| `IsUsingFallback` | Whether the shared store is the fallback. |
| `CreateProvider(options)` | Creates a new provider. **Expensive** (PBKDF2) — call once. |

### `AddNativeSecrets`

Registers `IKeychainStore` as a singleton. Disposed automatically by the DI container.

---

## FAQ

**Is the secret encrypted at rest?**
Yes, on every platform. Native stores handle it; the fallback uses AES-256-GCM.

**Can I read the secret from another machine?**
- Windows, Android: **no**.
- macOS / iOS: **yes**, if iCloud Keychain is enabled (the default implementation doesn't sync).
- Linux: depends on the keyring.
- Fallback: **no** — key is machine-bound.

**What happens if the user reinstalls the app?**
- Windows: secrets survive (Credential Manager is per-user, not per-app).
- Android: secrets are lost (Keystore is wiped on uninstall).
- iOS: secrets survive (Keychain persists across reinstall unless the app is deleted from iCloud backup settings).
- Fallback: survives (it's just a file).

**Can I use this in a console app?**
Yes. `KeychainFactory.Instance` works without any DI container.

**Can I use this in a library?**
Yes — depend on `NativeSecrets.Abstractions` only and accept `IKeychainStore` in your public API. Let the host application call `AddNativeSecrets()`.

**Does it work offline?**
Yes, everything is local. No network calls.

**Does it support trimming / AOT?**
Yes, the library is trim- and AOT-compatible.

**What about `SecureString`?**
Not used. `SecureString` is deprecated and does not provide meaningful protection on .NET Core. Secrets are passed as `string`; internal byte buffers are zeroed after use.

---

## API reference (short)

```csharp
public interface IKeychainStore
{
    bool IsAvailable(TimeSpan? timeout = null);

    void SetPassword(string package, string service, string user, string password);
    string? GetPassword(string package, string service, string user);
    bool DeletePassword(string package, string service, string user);

    Task SetPasswordAsync(string package, string service, string user, string password, CancellationToken ct = default);
    Task<string?> GetPasswordAsync(string package, string service, string user, CancellationToken ct = default);
    Task<bool> DeletePasswordAsync(string package, string service, string user, CancellationToken ct = default);
}
```

Obtain an instance:

```csharp
// Without DI
IKeychainStore store = KeychainFactory.Instance;

// With DI
services.AddNativeSecrets();
// then inject IKeychainStore anywhere
```

---

## Platform notes

### Windows

Uses **Credential Manager** (`CRED_TYPE_GENERIC`, `CRED_PERSIST_LOCAL_MACHINE`). Credentials are visible in `Control Panel → Credential Manager → Windows Credentials` under the target name `package/service/user`.

### macOS

Uses **Keychain** via `Security.framework`. Access prompts may appear on first access per application identity.

### Linux

Requires **libsecret** and a running Secret Service daemon (GNOME Keyring, KWallet, KeePassXC, etc.).

```bash
sudo apt install libsecret-1-0
```

In headless environments (Docker, CI) without a keyring, `IsAvailable()` returns `false` and the fallback is used automatically.

### Android

Uses **Android Keystore** (AES-256-GCM, hardware-backed when available) and stores the encrypted payload in `SharedPreferences`. Requires **API 23+**. The keystore key is non-exportable and survives app updates but **not** app uninstall or device factory reset.

### iOS / Mac Catalyst

Uses **Keychain** via `Security.framework`. Items are accessible after first unlock (`SecAccessible.AfterFirstUnlock`).

---

## Security considerations

- **Secrets are held in managed `string` objects** by the public API — GC may keep copies in memory. If this matters, keep secrets in `byte[]` on your side.
- **Zeroing**: byte buffers used internally are zeroed with `CryptographicOperations.ZeroMemory` after use.
- **Fallback is machine-bound**: the derived key depends on machine/user/device identifiers. Backups across machines will not decrypt.
- **Fallback file permissions**: `0600` on Unix (best effort — depends on the filesystem).
- **Availability probe** on Android/iOS writes a temporary `__nativesecrets_probe__` entry and deletes it in a `finally` block.

---

## Building from source

```bash
dotnet build -c Release
dotnet test
dotnet pack -c Release
```

Target frameworks: `net9.0`, `net9.0-windows`, `net9.0-android`, `net9.0-ios`, `net9.0-maccatalyst`.

---

## License

MIT.
