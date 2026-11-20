<div align="center">
  <img src="../ns.png" alt="NativeSecrets Logo" width="100" height="100" />
  <h1>NativeSecrets</h1>
  <p>
    <a href="https://www.nuget.org/packages/NativeSecrets"><img src="https://img.shields.io/nuget/v/NativeSecrets" alt="NuGet" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue" alt="License: MIT" /></a>
  </p>
  <p>
    <a href="../README.md">English</a> | <strong>Русский</strong>
  </p>
</div>

Кроссплатформенная .NET-библиотека для хранения секретов (токенов, паролей, API-ключей) в нативных системных хранилищах ОС с автоматическим откатом (fallback) на локальный зашифрованный файл.

Подходит для любых приложений на **.NET 8 / 9 / 10 / 11**: CLI-утилит, фоновых служб, ASP.NET Core, Avalonia, .NET MAUI, WPF и WinForms. Не использует рефлексию (`[LibraryImport]`, Source-Generated JSON) и полностью совместима с **Native AOT** и **Trimming**.

---

## Установка

```bash
dotnet add package NativeSecrets
```

---

## Поддерживаемые платформы

При первом обращении `NativeSecrets` проверяет доступность нативного хранилища (`IsAvailable`). Если системный менеджер паролей недоступен (например, в Docker-контейнере, headless-сервере или CI без D-Bus), библиотека автоматически переключается на резервное файловое хранилище.

| Платформа | Мин. версия | Нативное хранилище | Реализация |
| :--- | :--- | :--- | :--- |
| **Windows** | Windows 10+ | Windows Credential Manager | `advapi32.dll` (`CredWriteW` / `CredReadW` / `CredDeleteW`, `CRED_TYPE_GENERIC`) |
| **macOS** | macOS 12+ | Apple Keychain | `Security.framework` + `CoreFoundation` (`kSecClassGenericPassword`) |
| **iOS / Mac Catalyst** | iOS 15.0+ (.NET 10/11) | iOS Keychain | `Security` (`SecKind.GenericPassword`, `SecAccessible.AfterFirstUnlock`) |
| **Linux** | Любой с `libsecret` | Secret Service API (D-Bus) | `libsecret-1.so.0` (GNOME Keyring / KWallet) |
| **Android** | Android 6.0 / API 23+ (.NET 10)<br>Android 7.0 / API 24+ (.NET 11) | Android Keystore | Ключ-обёртка RSA-2048 в `AndroidKeyStore` + шифротекст AES-256-GCM в приватных `SharedPreferences` |
| **Fallback (все ОС)** | .NET 8 / 9 / 10 / 11 | Зашифрованный файл `secrets.bin` | AES-256-GCM, ключ выводится через PBKDF2-SHA256 (200 000 итераций) с привязкой к машине, пользователю и ID устройства |

---

## Использование

### 1. Быстрый старт (без DI)

Для большинства сценариев достаточно статического синглтона `KeychainFactory.Instance`. Он лениво и потокобезопасно инициализирует хранилище при первом вызове.

```csharp
using NativeSecrets.Core;

const string package = "com.example.MyApp";
const string service = "ApiTokens";
const string user = "default";

// Запись секрета
await KeychainFactory.Instance.SetPasswordAsync(package, service, user, "secret-token-123");

// Чтение секрета (вернёт null, если запись не найдена)
string? token = await KeychainFactory.Instance.GetPasswordAsync(package, service, user);

// Удаление секрета (вернёт true, если запись существовала)
bool deleted = await KeychainFactory.Instance.DeletePasswordAsync(package, service, user);

// Проверка, используется ли резервное файловое хранилище
bool isFallback = KeychainFactory.IsUsingFallback;
```

> Также доступны синхронные методы `SetPassword`, `GetPassword` и `DeletePassword`. Для UI-приложений рекомендуется использовать `*Async` перегрузки.

---

### 2. Использование с Dependency Injection

Зарегистрируйте `IKeychainStore` как Singleton с помощью `AddNativeSecrets`:

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

// Получаем IKeychainStore из контейнера
var store = serviceProvider.GetRequiredService<IKeychainStore>();
await store.SetPasswordAsync("com.example.MyApp", "Database", "admin", "P@ssw0rd!");

// При необходимости проверить тип хранилища можно через приведение к KeychainStoreProvider
if (store is KeychainStoreProvider { IsUsingFallback: true })
{
    Console.WriteLine("Используется резервное файловое хранилище.");
}
```

Внедрение в прикладные классы:

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

### 3. Кастомная конфигурация без DI (`CreateProvider`)

Если нужно настроить директорию для fallback-файла, принудительно включить файловое хранилище (например, в тестах) или передать логгер без DI:

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

> **Примечание по производительности:** инициализация `EncryptedFileFallbackStore` выполняет 200 000 итераций PBKDF2-SHA256. Создавайте провайдер один раз и переиспользуйте его на протяжении жизни приложения.

---

## Параметры `KeychainOptions`

| Свойство | По умолчанию | Описание |
| :--- | :--- | :--- |
| `ForceFallback` | `false` | Игнорирует нативные хранилища ОС и сразу использует файловый fallback. |
| `FallbackDirectory` | `%APPDATA%/NativeSecrets` | Директория для хранения `secrets.bin`. |
| `FallbackStore` | `null` | Собственная реализация `IKeychainStore` для fallback (удобно для моков в юнит-тестах). |
| `Logger` | `NullLogger.Instance` | Экземпляр `Microsoft.Extensions.Logging.ILogger`. |
| `AvailabilityTimeout` | `5 секунд` | Таймаут проверки доступности нативного хранилища (`IsAvailable`). |

---

## Правила валидации ключей и паролей

* **`package`** — непустая строка без пробельных символов (уникальный ID приложения, например `com.company.App`).
* **`service`** — непустая строка без пробельных символов (группа секретов, например `GitHub`, `Stripe`).
* **`user`** — не может быть `null`, но может быть пустой строкой `""` (если секрет общий для всего приложения).
* **`password`** — не может быть `null`, но может быть пустой строкой `""`.

При передаче некорректных значений выбрасывается `ArgumentException` или `ArgumentNullException`.

---

## Особенности платформ и безопасность

* **Linux:** требуется установленная системная библиотека `libsecret-1` (`libsecret-1-0` в Debian/Ubuntu, `libsecret` в Fedora/Arch) и запущенный демон Secret Service (`gnome-keyring-daemon` или аналог). В окружениях без D-Bus/GUI автоматически активируется `EncryptedFileFallbackStore`.
* **Непереносимость fallback-файла:** ключ шифрования `secrets.bin` привязывается к имени машины, имени пользователя и системному ID устройства (`/etc/machine-id` в Linux, `IOPlatformUUID` в macOS, `MachineGuid` в Windows). Файл нельзя расшифровать на другой машине или под другой учётной записью.
* **Защита памяти и файлов:** буферы с секретами в памяти очищаются через `CryptographicOperations.ZeroMemory`. На Unix-системах для директории и файла fallback-хранилища устанавливаются права доступа `0700` и `0600`, запись выполняется атомарно.

---

## Лицензия

[MIT](../LICENSE)
