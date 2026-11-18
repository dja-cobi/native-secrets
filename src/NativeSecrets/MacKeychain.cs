using System.Runtime.InteropServices;
using System.Text;

namespace NativeSecrets;

internal sealed unsafe partial class MacKeychain : IKeychainStore
{
    private const string SecurityLib = "/System/Library/Frameworks/Security.framework/Security";
    private const string CoreFoundationLib = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const int ErrSecSuccess = 0;
    private const int ErrSecItemNotFound = -25300;
    private const int ErrSecDuplicateItem = -25299;
    private static readonly IntPtr KCfAllocatorDefault = IntPtr.Zero;
    private static readonly IntPtr KCfAllocatorNull = IntPtr.Zero;

    [LibraryImport(SecurityLib)]
    private static partial int SecKeychainAddGenericPassword(IntPtr keychain, uint serviceLen, byte* service,
        uint accountLen, byte* account,
        uint passwordLen, byte* password, out IntPtr itemRef);

    [LibraryImport(SecurityLib)]
    private static partial int SecKeychainFindGenericPassword(
        IntPtr keychain, uint serviceLen, byte* service,
        uint accountLen, byte* account,
        out uint passwordLen, out IntPtr passwordData, out IntPtr itemRef);

    [LibraryImport(SecurityLib)]
    private static partial int SecKeychainItemModifyAttributesAndData(
        IntPtr itemRef, IntPtr attrList, uint length, byte* data);

    [LibraryImport(SecurityLib)]
    private static partial int SecKeychainItemDelete(IntPtr itemRef);

    [LibraryImport(SecurityLib)]
    private static partial int SecKeychainItemFreeContent(IntPtr attrList, IntPtr data);

    [LibraryImport(CoreFoundationLib)]
    private static partial void CFRelease(IntPtr cf);

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    
    private static string BuildService(string package, string service) => $"{package}/{service}";
    public bool IsAvailable()
    {
        var svc = Utf8("__vault_probe__");
        var acc = Utf8("__probe__");
        fixed (byte* pSvc = svc)
        fixed (byte* pAcc = acc)
        {
            var status = SecKeychainFindGenericPassword(IntPtr.Zero, (uint)svc.Length, pSvc,
                (uint)acc.Length, pAcc,
                out var len, out var pwd, out var item);

            if (pwd != IntPtr.Zero) SecKeychainItemFreeContent(IntPtr.Zero, pwd);
            if (item != IntPtr.Zero) CFRelease(item);

            return status is ErrSecSuccess or ErrSecItemNotFound;
        }
    }

    public void SetPassword(string package, string service, string user, string password)
    {
        var svc = BuildService(package, service);
        var svcB = Utf8(svc);
        var accB = Utf8(user);
        var pwdB = Utf8(password);

        fixed (byte* pSvc = svcB)
        fixed (byte* pAcc = accB)
        fixed (byte* pPwd = pwdB)
        {
            var status = SecKeychainAddGenericPassword(
                IntPtr.Zero, (uint)svcB.Length, pSvc,
                (uint)accB.Length, pAcc,
                (uint)pwdB.Length, pPwd, out var item);

            if (status == ErrSecDuplicateItem)
            {
                // Обновляем существующий элемент
                if (SecKeychainFindGenericPassword(
                        IntPtr.Zero, (uint)svcB.Length, pSvc,
                        (uint)accB.Length, pAcc,
                        out _, out var oldPwd, out var existing) != ErrSecSuccess)
                    throw new InvalidOperationException("Не удалось прочитать существующий ключ.");

                try
                {
                    status = SecKeychainItemModifyAttributesAndData(
                        existing, IntPtr.Zero, (uint)pwdB.Length, pPwd);
                }
                finally
                {
                    if (oldPwd != IntPtr.Zero) SecKeychainItemFreeContent(IntPtr.Zero, oldPwd);
                    if (existing != IntPtr.Zero) CFRelease(existing);
                }
            }

            if (item != IntPtr.Zero) CFRelease(item);

            if (status != ErrSecSuccess)
                throw new InvalidOperationException($"Keychain add failed: {status}");
        }
    }

    public string? GetPassword(string package, string service, string user)
    {
        var svc = BuildService(package, service);
        var svcB = Utf8(svc);
        var accB = Utf8(user);

        fixed (byte* pSvc = svcB)
        fixed (byte* pAcc = accB)
        {
            var status = SecKeychainFindGenericPassword(
                IntPtr.Zero, (uint)svcB.Length, pSvc,
                (uint)accB.Length, pAcc,
                out var len, out var pwd, out var item);

            if (status == ErrSecItemNotFound) return null;
            if (status != ErrSecSuccess)
                throw new InvalidOperationException($"Keychain find failed: {status}");

            try
            {
                if (pwd == IntPtr.Zero || len == 0) return string.Empty;
                return Encoding.UTF8.GetString((byte*)pwd, (int)len);
            }
            finally
            {
                if (pwd != IntPtr.Zero) SecKeychainItemFreeContent(IntPtr.Zero, pwd);
                if (item != IntPtr.Zero) CFRelease(item);
            }
        }
    }

    public bool DeletePassword(string package, string service, string user)
    {
        var svc = BuildService(package, service);
        var svcB = Utf8(svc);
        var accB = Utf8(user);

        fixed (byte* pSvc = svcB)
        fixed (byte* pAcc = accB)
        {
            var status = SecKeychainFindGenericPassword(
                IntPtr.Zero, (uint)svcB.Length, pSvc,
                (uint)accB.Length, pAcc,
                out _, out var pwd, out var item);

            if (status == ErrSecItemNotFound) return false;
            if (status != ErrSecSuccess)
                throw new InvalidOperationException($"Keychain find failed: {status}");

            try
            {
                if (pwd != IntPtr.Zero) SecKeychainItemFreeContent(IntPtr.Zero, pwd);
                if (item != IntPtr.Zero)
                {
                    var del = SecKeychainItemDelete(item);
                    if (del != ErrSecSuccess)
                        throw new InvalidOperationException($"Keychain delete failed: {del}");
                }
            }
            finally
            {
                if (item != IntPtr.Zero) CFRelease(item);
            }

            return true;
        }
    }
}
