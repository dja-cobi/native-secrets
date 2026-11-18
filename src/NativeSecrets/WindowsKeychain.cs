using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace NativeSecrets;

internal sealed unsafe partial class WindowsKeychain : IKeychainStore
{
    private const uint CRED_TYPE_GENERIC = 1;
    private const uint CRED_PERSIST_LOCAL_MACHINE = 2;
    private const int ERROR_NOT_FOUND = 1168;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIALW
    {
        public uint Flags;
        public uint Type;
        public char* TargetName;
        public char* Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public byte* CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public void* Attributes;
        public char* TargetAlias;
        public char* UserName;
    }

    [LibraryImport("advapi32.dll", EntryPoint = "CredWriteW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredWriteW(CREDENTIALW* credential, uint flags);

    [LibraryImport("advapi32.dll", EntryPoint = "CredReadW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredReadW(string target, uint type, uint flags, out CREDENTIALW* credential);

    [LibraryImport("advapi32.dll", EntryPoint = "CredDeleteW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredDeleteW(string target, uint type, uint flags);

    [LibraryImport("advapi32.dll", EntryPoint = "CredFree")]
    private static partial void CredFree(void* buffer);

    private static string BuildTarget(string package, string service, string user) => $"{package}/{service}/{user}";

    public bool IsAvailable()
    {
        try
        {
            if (CredReadW("__vault_probe__", CRED_TYPE_GENERIC, 0, out var cred))
            {
                CredFree(cred);
                return true;
            }

            var err = Marshal.GetLastPInvokeError();
            return err == ERROR_NOT_FOUND;
        }
        catch
        {
            return false;
        }
    }

    public void SetPassword(string package, string service, string user, string password)
    {
        var target = BuildTarget(package, service, user);
        var blob = Encoding.UTF8.GetBytes(password);

        try
        {
            fixed (char* pTarget = target)
            fixed (char* pUser = user)
            fixed (byte* pBlob = blob)
            {
                var cred = new CREDENTIALW
                {
                    Type = CRED_TYPE_GENERIC,
                    TargetName = pTarget,
                    Comment = null,
                    Persist = CRED_PERSIST_LOCAL_MACHINE,
                    CredentialBlobSize = (uint)blob.Length,
                    CredentialBlob = blob.Length > 0 ? pBlob : null,
                    UserName = pUser
                };

                if (!CredWriteW(&cred, 0))
                    throw new InvalidOperationException($"CredWriteW failed: {Marshal.GetLastPInvokeError()}");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(blob);
        }
    }

    public string? GetPassword(string package, string service, string user)
    {
        var target = BuildTarget(package, service, user);
        if (!CredReadW(target, CRED_TYPE_GENERIC, 0, out var cred))
        {
            var err = Marshal.GetLastPInvokeError();
            return err == ERROR_NOT_FOUND ? null : throw new InvalidOperationException($"CredReadW failed: {err}");
        }

        try
        {
            if (cred->CredentialBlob == null || cred->CredentialBlobSize == 0)
                return string.Empty;

            return Encoding.UTF8.GetString(cred->CredentialBlob, (int)cred->CredentialBlobSize);
        }
        finally
        {
            CredFree(cred);
        }
    }

    public bool DeletePassword(string package, string service, string user)
    {
        var target = BuildTarget(package, service, user);
        if (CredDeleteW(target, CRED_TYPE_GENERIC, 0))
            return true;

        var err = Marshal.GetLastPInvokeError();
        return err == ERROR_NOT_FOUND ? false : throw new InvalidOperationException($"CredDeleteW failed: {err}");
    }
}


// using System.Runtime.InteropServices;
// using System.Security.Cryptography;
// using System.Text;
//
// namespace NativeSecrets;
//
// internal sealed unsafe partial class WindowsKeychain : IKeychainStore
// {
//     private const uint CRED_TYPE_GENERIC = 1;
//     private const uint CRED_PERSIST_LOCAL_MACHINE = 2;
//     private const int ERROR_NOT_FOUND = 1168;
//
//     [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
//     private struct CREDENTIALW
//     {
//         public uint Flags;
//         public uint Type;
//         public char* TargetName;
//         public char* Comment;
//         public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
//         public uint CredentialBlobSize;
//         public byte* CredentialBlob;
//         public uint Persist;
//         public uint AttributeCount;
//         public void* Attributes;
//         public char* TargetAlias;
//         public char* UserName;
//     }
//
//     [LibraryImport("advapi32.dll", EntryPoint = "CredWriteW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
//     [return: MarshalAs(UnmanagedType.Bool)]
//     private static partial bool CredWriteW(CREDENTIALW* credential, uint flags);
//
//     [LibraryImport("advapi32.dll", EntryPoint = "CredReadW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
//     [return: MarshalAs(UnmanagedType.Bool)]
//     private static partial bool CredReadW(string target, uint type, uint flags, out CREDENTIALW* credential);
//
//     [LibraryImport("advapi32.dll", EntryPoint = "CredDeleteW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
//     [return: MarshalAs(UnmanagedType.Bool)]
//     private static partial bool CredDeleteW(string target, uint type, uint flags);
//
//     [LibraryImport("advapi32.dll", EntryPoint = "CredFree")]
//     private static partial void CredFree(void* buffer);
//
//     private static string BuildTarget(string package, string service, string user) => $"{package}/{service}/{user}";
//
//     public bool IsAvailable()
//     {
//         try
//         {
//             if (CredReadW("__vault_probe__", CRED_TYPE_GENERIC, 0, out var cred))
//             {
//                 CredFree(cred);
//                 return true;
//             }
//
//             var err = Marshal.GetLastPInvokeError();
//             return err == ERROR_NOT_FOUND;
//         }
//         catch
//         {
//             return false;
//         }
//     }
//
//     public void SetPassword(string package, string service, string user, string password)
//     {
//         var target = BuildTarget(package, service, user);
//         var blob = Encoding.UTF8.GetBytes(password);
//
//         try
//         {
//             fixed (char* pTarget = target)
//             fixed (char* pUser = user)
//             fixed (byte* pBlob = blob)
//             {
//                 var cred = new CREDENTIALW
//                 {
//                     Type = CRED_TYPE_GENERIC,
//                     TargetName = pTarget,
//                     Comment = null,
//                     Persist = CRED_PERSIST_LOCAL_MACHINE,
//                     CredentialBlobSize = (uint)blob.Length,
//                     CredentialBlob = blob.Length > 0 ? pBlob : null,
//                     UserName = pUser
//                 };
//
//                 if (!CredWriteW(&cred, 0))
//                     throw new InvalidOperationException($"CredWriteW failed: {Marshal.GetLastPInvokeError()}");
//             }
//         }
//         finally
//         {
//             CryptographicOperations.ZeroMemory(blob);
//         }
//     }
//
//     public string? GetPassword(string package, string service, string user)
//     {
//         var target = BuildTarget(package, service, user);
//         if (!CredReadW(target, CRED_TYPE_GENERIC, 0, out var cred))
//         {
//             var err = Marshal.GetLastPInvokeError();
//             return err == ERROR_NOT_FOUND ? null : throw new InvalidOperationException($"CredReadW failed: {err}");
//         }
//
//         try
//         {
//             if (cred->CredentialBlob == null || cred->CredentialBlobSize == 0)
//                 return string.Empty;
//
//             return Encoding.UTF8.GetString(cred->CredentialBlob, (int)cred->CredentialBlobSize);
//         }
//         finally
//         {
//             CredFree(cred);
//         }
//     }
//
//     public bool DeletePassword(string package, string service, string user)
//     {
//         var target = BuildTarget(package, service, user);
//         if (CredDeleteW(target, CRED_TYPE_GENERIC, 0))
//             return true;
//
//         var err = Marshal.GetLastPInvokeError();
//         return err == ERROR_NOT_FOUND ? false : throw new InvalidOperationException($"CredDeleteW failed: {err}");
//     }
// }


// using System.Runtime.InteropServices;
// using System.Text;
//
// namespace NativeSecrets;
//
// internal sealed unsafe partial class WindowsKeychain : IKeychainStore
// {
//     private const uint CRED_TYPE_GENERIC = 1;
//     private const uint CRED_PERSIST_LOCAL_MACHINE = 2;
//     private const int ERROR_NOT_FOUND = 1168;
//     private const int ERROR_NO_SUCH_LOGON_SESSION = 1312;
//     
//     [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
//     private struct CREDENTIALW
//     {
//         public uint Flags;
//         public uint Type;
//         public char* TargetName;
//         public char* Comment;
//         public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
//         public uint CredentialBlobSize;
//         public byte* CredentialBlob;
//         public uint Persist;
//         public uint AttributeCount;
//         public void* Attributes;
//         public char* TargetAlias;
//         public char* UserName;
//     }
//     
//     [LibraryImport("advapi32.dll", EntryPoint = "CredWriteW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
//     [return: MarshalAs(UnmanagedType.Bool)]
//     private static partial bool CredWriteW(CREDENTIALW* credential, uint flags);
//     
//     [LibraryImport("advapi32.dll", EntryPoint = "CredWriteW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
//     [return: MarshalAs(UnmanagedType.Bool)]
//     private static partial bool CredReadW(string target, uint type, uint flags, out CREDENTIALW* credential);
//     
//     [LibraryImport("advapi32.dll", EntryPoint = "CredDeleteW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
//     [return: MarshalAs(UnmanagedType.Bool)]
//     private static partial bool CredDeleteW(string target, uint type, uint flags);
//
//     [LibraryImport("advapi32.dll", EntryPoint = "CredFree")]
//     private static partial void CredFree(void* buffer);
//     
//     private static string BuildTarget(string package, string service, string user) => $"{package}/{service}/{user}";
//     
//     public bool IsAvailable()
//     {
//         try
//         {
//             if (CredReadW("__vault_probe__", CRED_TYPE_GENERIC, 0, out var cred))
//             {
//                 CredFree(cred);
//                 return true;
//             }
//             
//             var err = Marshal.GetLastPInvokeError();
//             return err == ERROR_NOT_FOUND;
//         }
//         catch
//         {
//             return false;
//         }
//     }
//
//     public void SetPassword(string package, string service, string user, string password)
//     {
//         var target = BuildTarget(package, service, user);
//         var blob = Encoding.UTF8.GetBytes(password);
//         
//         fixed (char* pTarget = target)
//         fixed (char* pUser = user)
//         fixed (char* pComment = "")
//         fixed (byte* pBlob = blob)
//         {
//             var cred = new CREDENTIALW
//             {
//                 Type = CRED_TYPE_GENERIC,
//                 TargetName = pTarget,
//                 Comment = pComment,
//                 Persist = CRED_PERSIST_LOCAL_MACHINE,
//                 CredentialBlobSize = (uint)blob.Length,
//                 CredentialBlob = pBlob,
//                 UserName = pUser,
//             };
//
//             if (!CredWriteW(&cred, 0))
//                 throw new InvalidOperationException($"CredWriteW failed: {Marshal.GetLastPInvokeError()}");
//         }
//     }
//
//     public string? GetPassword(string package, string service, string user)
//     {
//         var target = BuildTarget(package, service, user);
//         if (!CredReadW(target, CRED_TYPE_GENERIC, 0, out var cred))
//         {
//             var err = Marshal.GetLastPInvokeError();
//             return err == ERROR_NOT_FOUND ? null : throw new InvalidOperationException($"CredReadW failed: {err}");
//         }
//
//         try
//         {
//             return Encoding.UTF8.GetString(cred->CredentialBlob, (int)cred->CredentialBlobSize);
//         }
//         finally
//         {
//             CredFree(cred);
//         }
//     }
//
//     public bool DeletePassword(string package, string service, string user)
//     {
//         var target = BuildTarget(package, service, user);
//         if (CredDeleteW(target, CRED_TYPE_GENERIC, 0))
//             return true;
//         
//         var err = Marshal.GetLastPInvokeError();
//         return err == ERROR_NOT_FOUND ? false : throw new InvalidOperationException($"CredDeleteW failed: {err}");
//     }
// }