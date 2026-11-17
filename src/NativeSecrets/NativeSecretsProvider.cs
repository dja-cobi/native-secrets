using System.Runtime.InteropServices;
using NativeSecrets.Exceptions;
using NativeSecrets.Interop;

namespace NativeSecrets;

/// <summary>
/// Provides cross-platform access to the native OS credential store (Windows Credential Manager, macOS Keychain, Linux libsecret).
/// </summary>
/// <param name="options">Configuration options for the secrets provider.</param>
public class NativeSecretsProvider(NativeSecretsOptions? options) : NativeSecretsBase
{
    private readonly NativeSecretsOptions _options = options ?? new NativeSecretsOptions();

    /// <inheritdoc />
    public override void SetSecret(string service, string account, string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(service);
        ArgumentException.ThrowIfNullOrEmpty(account);
        ArgumentException.ThrowIfNullOrEmpty(secret);

        NativeSecretsInterop.SetPassword(GetPackageName(), service, account, secret);
        CheckLastError(service, account);
    }

    /// <inheritdoc />
    public override string? GetSecret(string service, string account)
    {
        ArgumentException.ThrowIfNullOrEmpty(service);
        ArgumentException.ThrowIfNullOrEmpty(account);

        var ptr = NativeSecretsInterop.GetPassword(GetPackageName(), service, account);

        var errorCode = NativeSecretsInterop.GetLastError();
        switch (errorCode)
        {
            case 0:
                return ptr == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(ptr);
            case 2:
                return null;
            default:
                CheckLastError(service, account);
                return ptr == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(ptr);
        }
    }

    /// <inheritdoc />
    public override void DeleteSecret(string service, string account)
    {
        ArgumentException.ThrowIfNullOrEmpty(service);
        ArgumentException.ThrowIfNullOrEmpty(account);

        NativeSecretsInterop.DeletePassword(GetPackageName(), service, account);
        CheckLastError(service, account);
    }

    /// <inheritdoc />
    public override Task SetSecretAsync(string service, string account, string secret, CancellationToken ct = default) =>
        Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            SetSecret(service, account, secret);
        }, ct);

    /// <inheritdoc />
    public override Task<string?> GetSecretAsync(string service, string account, CancellationToken ct = default) =>
        Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            return GetSecret(service, account);
        }, ct);

    /// <inheritdoc />
    public override Task DeleteSecretAsync(string service, string account, CancellationToken ct = default) =>
        Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            DeleteSecret(service, account);
        }, ct);

    /// <inheritdoc />
    public override Task<bool> SecretExistsAsync(string service, string account, CancellationToken ct = default) =>
        Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            return SecretExists(service, account);
        }, ct);

    private string GetPackageName() => 
        string.IsNullOrWhiteSpace(_options.DefaultService) ? "NativeSecrets" : _options.DefaultService;

    private static void CheckLastError(string service, string account)
    {
        var resultCode = NativeSecretsInterop.GetLastError();
        if (resultCode == 0) return;

        var msgPtr = NativeSecretsInterop.GetLastErrorMessage();
        var message = msgPtr != IntPtr.Zero
            ? Marshal.PtrToStringUTF8(msgPtr) ?? $"Native keychain error. Code: {resultCode}"
            : $"Native keychain error. Code: {resultCode}";

        throw resultCode switch
        {
            2 => new SecretNotFoundException(service, account),
            3 => new SecretAccessDeniedException(),
            _ => new NativeSecretsException(message, resultCode)
        };
    }
}