using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace NativeSecrets;

internal sealed unsafe partial class MacKeychain : IKeychainStore
{
    private const string SecurityLib = "/System/Library/Frameworks/Security.framework/Security";
    private const string CoreFoundationLib = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

    private const int ErrSecSuccess = 0;
    private const int ErrSecItemNotFound = -25300;
    private const uint KcfStringEncodingUtf8 = 0x08000100;

    private static IntPtr _kSecClass;
    private static IntPtr _kSecClassGenericPassword;
    private static IntPtr _kSecAttrService;
    private static IntPtr _kSecAttrAccount;
    private static IntPtr _kSecValueData;
    private static IntPtr _kSecReturnData;
    private static IntPtr _kSecMatchLimit;
    private static IntPtr _kSecMatchLimitOne;
    private static IntPtr _kCfBooleanTrue;
    private static IntPtr _kCfTypeDictionaryKeyCallBacks;
    private static IntPtr _kCfTypeDictionaryValueCallBacks;
    private static bool _symbolsLoaded;

    private static void EnsureSymbolsLoaded()
    {
        if (_symbolsLoaded) return;

        var sec = NativeLibrary.Load(SecurityLib);
        var cf = NativeLibrary.Load(CoreFoundationLib);

        _kSecClass = Marshal.ReadIntPtr(NativeLibrary.GetExport(sec, "kSecClass"));
        _kSecClassGenericPassword = Marshal.ReadIntPtr(NativeLibrary.GetExport(sec, "kSecClassGenericPassword"));
        _kSecAttrService = Marshal.ReadIntPtr(NativeLibrary.GetExport(sec, "kSecAttrService"));
        _kSecAttrAccount = Marshal.ReadIntPtr(NativeLibrary.GetExport(sec, "kSecAttrAccount"));
        _kSecValueData = Marshal.ReadIntPtr(NativeLibrary.GetExport(sec, "kSecValueData"));
        _kSecReturnData = Marshal.ReadIntPtr(NativeLibrary.GetExport(sec, "kSecReturnData"));
        _kSecMatchLimit = Marshal.ReadIntPtr(NativeLibrary.GetExport(sec, "kSecMatchLimit"));
        _kSecMatchLimitOne = Marshal.ReadIntPtr(NativeLibrary.GetExport(sec, "kSecMatchLimitOne"));
        _kCfBooleanTrue = Marshal.ReadIntPtr(NativeLibrary.GetExport(cf, "kCFBooleanTrue"));

        _kCfTypeDictionaryKeyCallBacks = NativeLibrary.GetExport(cf, "kCFTypeDictionaryKeyCallBacks");
        _kCfTypeDictionaryValueCallBacks = NativeLibrary.GetExport(cf, "kCFTypeDictionaryValueCallBacks");

        _symbolsLoaded = true;
    }

    private static string BuildService(string package, string service) => $"{package}/{service}";

    public bool IsAvailable()
    {
        try
        {
            if (!OperatingSystem.IsMacOS()) return false;
            EnsureSymbolsLoaded();

            var query = CreateBaseQuery("__vault_probe__", "__probe__");
            try
            {
                var status = SecItemCopyMatching(query, out var result);
                if (result != IntPtr.Zero) CfRelease(result);
                return status is ErrSecSuccess or ErrSecItemNotFound;
            }
            finally
            {
                CfRelease(query);
            }
        }
        catch
        {
            return false;
        }
    }

    public void SetPassword(string package, string service, string user, string password)
    {
        EnsureSymbolsLoaded();
        var svc = BuildService(package, service);
        var pwdBytes = Encoding.UTF8.GetBytes(password);

        var query = CreateBaseQuery(svc, user);
        var valueData = CreateCfData(pwdBytes);

        try
        {
            var checkStatus = SecItemCopyMatching(query, out var existing);
            if (existing != IntPtr.Zero) CfRelease(existing);

            if (checkStatus == ErrSecSuccess)
            {
                var updateDict = CfDictionaryCreateMutable(
                    IntPtr.Zero, 1, _kCfTypeDictionaryKeyCallBacks, _kCfTypeDictionaryValueCallBacks);
                try
                {
                    CfDictionarySetValue(updateDict, _kSecValueData, valueData);
                    var updateStatus = SecItemUpdate(query, updateDict);
                    if (updateStatus != ErrSecSuccess)
                        throw new InvalidOperationException($"SecItemUpdate failed: {updateStatus}");
                }
                finally
                {
                    CfRelease(updateDict);
                }

                return;
            }

            CfDictionarySetValue(query, _kSecValueData, valueData);
            var addStatus = SecItemAdd(query, out var addedResult);
            if (addedResult != IntPtr.Zero) CfRelease(addedResult);

            if (addStatus != ErrSecSuccess)
                throw new InvalidOperationException($"SecItemAdd failed: {addStatus}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwdBytes);
            CfRelease(valueData);
            CfRelease(query);
        }
    }

    public string? GetPassword(string package, string service, string user)
    {
        EnsureSymbolsLoaded();
        var svc = BuildService(package, service);
        var query = CreateBaseQuery(svc, user);

        try
        {
            CfDictionarySetValue(query, _kSecReturnData, _kCfBooleanTrue);
            CfDictionarySetValue(query, _kSecMatchLimit, _kSecMatchLimitOne);

            var status = SecItemCopyMatching(query, out var result);
            if (status == ErrSecItemNotFound) return null;
            if (status != ErrSecSuccess)
                throw new InvalidOperationException($"SecItemCopyMatching failed: {status}");

            if (result == IntPtr.Zero) return null;

            try
            {
                var len = (int)CfDataGetLength(result);
                if (len <= 0) return string.Empty;

                var ptr = CfDataGetBytePtr(result);
                return Encoding.UTF8.GetString(ptr, len);
            }
            finally
            {
                CfRelease(result);
            }
        }
        finally
        {
            CfRelease(query);
        }
    }

    public bool DeletePassword(string package, string service, string user)
    {
        EnsureSymbolsLoaded();
        var svc = BuildService(package, service);
        var query = CreateBaseQuery(svc, user);

        try
        {
            var status = SecItemDelete(query);
            if (status == ErrSecItemNotFound) 
                return false;
            
            return status != ErrSecSuccess ? throw new InvalidOperationException($"SecItemDelete failed: {status}") : true;
        }
        finally
        {
            CfRelease(query);
        }
    }

    private static IntPtr CreateBaseQuery(string service, string account)
    {
        var dict = CfDictionaryCreateMutable(
            IntPtr.Zero, 4, _kCfTypeDictionaryKeyCallBacks, _kCfTypeDictionaryValueCallBacks);
        var cfService = CreateCfString(service);
        var cfAccount = CreateCfString(account);

        try
        {
            CfDictionarySetValue(dict, _kSecClass, _kSecClassGenericPassword);
            CfDictionarySetValue(dict, _kSecAttrService, cfService);
            CfDictionarySetValue(dict, _kSecAttrAccount, cfAccount);
            return dict;
        }
        finally
        {
            CfRelease(cfService);
            CfRelease(cfAccount);
        }
    }

    private static IntPtr CreateCfString(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        fixed (byte* ptr = bytes)
        {
            var cfStr = CfStringCreateWithBytes(IntPtr.Zero, ptr, bytes.Length, KcfStringEncodingUtf8, false);
            return cfStr == IntPtr.Zero ? throw new OutOfMemoryException("CFStringCreateWithBytes failed.") : cfStr;
        }
    }

    private static IntPtr CreateCfData(byte[] data)
    {
        fixed (byte* ptr = data)
        {
            var cfData = CfDataCreate(IntPtr.Zero, ptr, data.Length);
            return cfData == IntPtr.Zero ? throw new OutOfMemoryException("CFDataCreate failed.") : cfData;
        }
    }

    [LibraryImport(SecurityLib, EntryPoint = "SecItemAdd")]
    private static partial int SecItemAdd(IntPtr attributes, out IntPtr result);

    [LibraryImport(SecurityLib, EntryPoint = "SecItemCopyMatching")]
    private static partial int SecItemCopyMatching(IntPtr query, out IntPtr result);

    [LibraryImport(SecurityLib, EntryPoint = "SecItemUpdate")]
    private static partial int SecItemUpdate(IntPtr query, IntPtr attributesToUpdate);

    [LibraryImport(SecurityLib, EntryPoint = "SecItemDelete")]
    private static partial int SecItemDelete(IntPtr query);

    [LibraryImport(CoreFoundationLib, EntryPoint = "CFDictionaryCreateMutable")]
    private static partial IntPtr CfDictionaryCreateMutable(
        IntPtr allocator, nint capacity, IntPtr keyCallBacks, IntPtr valueCallBacks);

    [LibraryImport(CoreFoundationLib, EntryPoint = "CFDictionarySetValue")]
    private static partial void CfDictionarySetValue(IntPtr theDict, IntPtr key, IntPtr value);

    [LibraryImport(CoreFoundationLib, EntryPoint = "CFStringCreateWithBytes")]
    private static partial IntPtr CfStringCreateWithBytes(
        IntPtr allocator, byte* bytes, nint numBytes, uint encoding,
        [MarshalAs(UnmanagedType.U1)] bool isExternalRepresentation);

    [LibraryImport(CoreFoundationLib, EntryPoint = "CFDataCreate")]
    private static partial IntPtr CfDataCreate(IntPtr allocator, byte* bytes, nint length);

    [LibraryImport(CoreFoundationLib, EntryPoint = "CFDataGetLength")]
    private static partial nint CfDataGetLength(IntPtr theData);

    [LibraryImport(CoreFoundationLib, EntryPoint = "CFDataGetBytePtr")]
    private static partial byte* CfDataGetBytePtr(IntPtr theData);

    [LibraryImport(CoreFoundationLib, EntryPoint = "CFRelease")]
    private static partial void CfRelease(IntPtr cf);
}



// using System.Runtime.InteropServices;
// using System.Text;
//
// namespace NativeSecrets;
//
// internal sealed unsafe partial class MacKeychain : IKeychainStore
// {
//     private const string SecurityLib = "/System/Library/Frameworks/Security.framework/Security";
//     private const string CoreFoundationLib = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
//     private const int ErrSecSuccess = 0;
//     private const int ErrSecItemNotFound = -25300;
//     private const int ErrSecDuplicateItem = -25299;
//     private static readonly IntPtr KCfAllocatorDefault = IntPtr.Zero;
//     private static readonly IntPtr KCfAllocatorNull = IntPtr.Zero;
//
//     [LibraryImport(SecurityLib)]
//     private static partial int SecKeychainAddGenericPassword(IntPtr keychain, uint serviceLen, byte* service,
//         uint accountLen, byte* account,
//         uint passwordLen, byte* password, out IntPtr itemRef);
//
//     [LibraryImport(SecurityLib)]
//     private static partial int SecKeychainFindGenericPassword(
//         IntPtr keychain, uint serviceLen, byte* service,
//         uint accountLen, byte* account,
//         out uint passwordLen, out IntPtr passwordData, out IntPtr itemRef);
//
//     [LibraryImport(SecurityLib)]
//     private static partial int SecKeychainItemModifyAttributesAndData(
//         IntPtr itemRef, IntPtr attrList, uint length, byte* data);
//
//     [LibraryImport(SecurityLib)]
//     private static partial int SecKeychainItemDelete(IntPtr itemRef);
//
//     [LibraryImport(SecurityLib)]
//     private static partial int SecKeychainItemFreeContent(IntPtr attrList, IntPtr data);
//
//     [LibraryImport(CoreFoundationLib)]
//     private static partial void CFRelease(IntPtr cf);
//
//     private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
//
//     
//     private static string BuildService(string package, string service) => $"{package}/{service}";
//     public bool IsAvailable()
//     {
//         var svc = Utf8("__vault_probe__");
//         var acc = Utf8("__probe__");
//         fixed (byte* pSvc = svc)
//         fixed (byte* pAcc = acc)
//         {
//             var status = SecKeychainFindGenericPassword(IntPtr.Zero, (uint)svc.Length, pSvc,
//                 (uint)acc.Length, pAcc,
//                 out var len, out var pwd, out var item);
//
//             if (pwd != IntPtr.Zero) SecKeychainItemFreeContent(IntPtr.Zero, pwd);
//             if (item != IntPtr.Zero) CFRelease(item);
//
//             return status is ErrSecSuccess or ErrSecItemNotFound;
//         }
//     }
//
//     public void SetPassword(string package, string service, string user, string password)
//     {
//         var svc = BuildService(package, service);
//         var svcB = Utf8(svc);
//         var accB = Utf8(user);
//         var pwdB = Utf8(password);
//
//         fixed (byte* pSvc = svcB)
//         fixed (byte* pAcc = accB)
//         fixed (byte* pPwd = pwdB)
//         {
//             var status = SecKeychainAddGenericPassword(
//                 IntPtr.Zero, (uint)svcB.Length, pSvc,
//                 (uint)accB.Length, pAcc,
//                 (uint)pwdB.Length, pPwd, out var item);
//
//             if (status == ErrSecDuplicateItem)
//             {
//                 // Обновляем существующий элемент
//                 if (SecKeychainFindGenericPassword(
//                         IntPtr.Zero, (uint)svcB.Length, pSvc,
//                         (uint)accB.Length, pAcc,
//                         out _, out var oldPwd, out var existing) != ErrSecSuccess)
//                     throw new InvalidOperationException("Не удалось прочитать существующий ключ.");
//
//                 try
//                 {
//                     status = SecKeychainItemModifyAttributesAndData(
//                         existing, IntPtr.Zero, (uint)pwdB.Length, pPwd);
//                 }
//                 finally
//                 {
//                     if (oldPwd != IntPtr.Zero) SecKeychainItemFreeContent(IntPtr.Zero, oldPwd);
//                     if (existing != IntPtr.Zero) CFRelease(existing);
//                 }
//             }
//
//             if (item != IntPtr.Zero) CFRelease(item);
//
//             if (status != ErrSecSuccess)
//                 throw new InvalidOperationException($"Keychain add failed: {status}");
//         }
//     }
//
//     public string? GetPassword(string package, string service, string user)
//     {
//         var svc = BuildService(package, service);
//         var svcB = Utf8(svc);
//         var accB = Utf8(user);
//
//         fixed (byte* pSvc = svcB)
//         fixed (byte* pAcc = accB)
//         {
//             var status = SecKeychainFindGenericPassword(
//                 IntPtr.Zero, (uint)svcB.Length, pSvc,
//                 (uint)accB.Length, pAcc,
//                 out var len, out var pwd, out var item);
//
//             if (status == ErrSecItemNotFound) return null;
//             if (status != ErrSecSuccess)
//                 throw new InvalidOperationException($"Keychain find failed: {status}");
//
//             try
//             {
//                 if (pwd == IntPtr.Zero || len == 0) return string.Empty;
//                 return Encoding.UTF8.GetString((byte*)pwd, (int)len);
//             }
//             finally
//             {
//                 if (pwd != IntPtr.Zero) SecKeychainItemFreeContent(IntPtr.Zero, pwd);
//                 if (item != IntPtr.Zero) CFRelease(item);
//             }
//         }
//     }
//
//     public bool DeletePassword(string package, string service, string user)
//     {
//         var svc = BuildService(package, service);
//         var svcB = Utf8(svc);
//         var accB = Utf8(user);
//
//         fixed (byte* pSvc = svcB)
//         fixed (byte* pAcc = accB)
//         {
//             var status = SecKeychainFindGenericPassword(
//                 IntPtr.Zero, (uint)svcB.Length, pSvc,
//                 (uint)accB.Length, pAcc,
//                 out _, out var pwd, out var item);
//
//             if (status == ErrSecItemNotFound) return false;
//             if (status != ErrSecSuccess)
//                 throw new InvalidOperationException($"Keychain find failed: {status}");
//
//             try
//             {
//                 if (pwd != IntPtr.Zero) SecKeychainItemFreeContent(IntPtr.Zero, pwd);
//                 if (item != IntPtr.Zero)
//                 {
//                     var del = SecKeychainItemDelete(item);
//                     if (del != ErrSecSuccess)
//                         throw new InvalidOperationException($"Keychain delete failed: {del}");
//                 }
//             }
//             finally
//             {
//                 if (item != IntPtr.Zero) CFRelease(item);
//             }
//
//             return true;
//         }
//     }
// }
