using System.Runtime.InteropServices;
using System.Text;
using NativeSecrets.Abstractions;

namespace NativeSecrets.Platforms;

internal sealed unsafe partial class LinuxKeychain : IKeychainStore, IDisposable
{
    private const string LibSecret = "libsecret-1.so.0";
    private const string LibGlib = "libglib-2.0.so.0";
    private const string LibGObject = "libgobject-2.0.so.0";

    private static readonly byte[] CollectionDefault = [.. "default\0"u8];
    private static readonly byte[] ServiceFieldName = [.. "service\0"u8];
    private static readonly byte[] AccountFieldName = [.. "username\0"u8];

    private bool _disposed;

    public bool IsAvailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, nameof(LinuxKeychain));

        var err = IntPtr.Zero;
        var service = IntPtr.Zero;

        try
        {
            service = secret_service_get_sync(0, IntPtr.Zero, out err);
            if (err != IntPtr.Zero) return false;
            return service != IntPtr.Zero;
        }
        finally
        {
            if (service != IntPtr.Zero) g_object_unref(service);
            if (err != IntPtr.Zero) g_error_free(err);
        }
    }

    public void SetPassword(string package, string service, string user, string password)
    {
        ValidateArguments(package, service, password);

        var labelText = string.IsNullOrEmpty(user) ? service : $"{service} ({user})";

        using var pkgHandle = Utf8StringHandle.Create(package);
        using var svcHandle = Utf8StringHandle.Create(service);
        using var usrHandle = Utf8StringHandle.Create(user);
        using var pwdHandle = Utf8StringHandle.Create(password);
        using var lblHandle = Utf8StringHandle.Create(labelText);

        var err = IntPtr.Zero;
        try
        {
            fixed (byte* pPkg = pkgHandle.Buffer)
            fixed (byte* pSvc = svcHandle.Buffer)
            fixed (byte* pUsr = usrHandle.Buffer)
            fixed (byte* pPwd = pwdHandle.Buffer)
            fixed (byte* pLbl = lblHandle.Buffer)
            fixed (byte* pCol = CollectionDefault)
            fixed (byte* pFieldSvc = ServiceFieldName)
            fixed (byte* pFieldAcc = AccountFieldName)
            {
                var schema = MakeSchema(pPkg, pFieldSvc, pFieldAcc);
                var ok = secret_password_store_sync(
                    &schema, pCol, pLbl, pPwd, IntPtr.Zero, out err,
                    pFieldSvc, pSvc, pFieldAcc, pUsr, IntPtr.Zero);

                ThrowIfError(err, ok == 0, "secret_password_store_sync failed");
            }
        }
        finally
        {
            if (err != IntPtr.Zero) g_error_free(err);
        }
    }

    public string? GetPassword(string package, string service, string? user)
    {
        ValidateArguments(package, service);

        using var pkgHandle = Utf8StringHandle.Create(package);
        using var svcHandle = Utf8StringHandle.Create(service);
        using var usrHandle = Utf8StringHandle.Create(user ?? string.Empty);

        var err = IntPtr.Zero;
        var rawPassword = IntPtr.Zero;

        try
        {
            fixed (byte* pPkg = pkgHandle.Buffer)
            fixed (byte* pSvc = svcHandle.Buffer)
            fixed (byte* pUsr = usrHandle.Buffer)
            fixed (byte* pFieldSvc = ServiceFieldName)
            fixed (byte* pFieldAcc = AccountFieldName)
            {
                var schema = MakeSchema(pPkg, pFieldSvc, pFieldAcc);
                rawPassword = secret_password_lookup_sync(
                    &schema, IntPtr.Zero, out err,
                    pFieldSvc, pSvc, pFieldAcc, pUsr, IntPtr.Zero);

                ThrowIfError(err, false, "secret_password_lookup_sync failed");

                return rawPassword == IntPtr.Zero
                    ? null
                    : Marshal.PtrToStringUTF8(rawPassword);
            }
        }
        finally
        {
            if (rawPassword != IntPtr.Zero) secret_password_free(rawPassword);
            if (err != IntPtr.Zero) g_error_free(err);
        }
    }

    public bool DeletePassword(string package, string service, string? user)
    {
        ValidateArguments(package, service);

        using var pkgHandle = Utf8StringHandle.Create(package);
        using var svcHandle = Utf8StringHandle.Create(service);
        using var usrHandle = Utf8StringHandle.Create(user ?? string.Empty);

        var err = IntPtr.Zero;
        try
        {
            fixed (byte* pPkg = pkgHandle.Buffer)
            fixed (byte* pSvc = svcHandle.Buffer)
            fixed (byte* pUsr = usrHandle.Buffer)
            fixed (byte* pFieldSvc = ServiceFieldName)
            fixed (byte* pFieldAcc = AccountFieldName)
            {
                var schema = MakeSchema(pPkg, pFieldSvc, pFieldAcc);
                var deleted = secret_password_clear_sync(
                    &schema, IntPtr.Zero, out err,
                    pFieldSvc, pSvc, pFieldAcc, pUsr, IntPtr.Zero);

                ThrowIfError(err, false, "secret_password_clear_sync failed");
                return deleted != 0;
            }
        }
        finally
        {
            if (err != IntPtr.Zero) g_error_free(err);
        }
    }

    public void Dispose()
    {
        if (!_disposed) _disposed = true;
    }

    private static void ValidateArguments(string package, string service, string? password = null)
    {
        if (string.IsNullOrWhiteSpace(package))
            throw new ArgumentException("Package name cannot be null or empty", nameof(package));
        if (string.IsNullOrWhiteSpace(service))
            throw new ArgumentException("Service name cannot be null or empty", nameof(service));
        if (password != null && string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be empty", nameof(password));
    }

    private static SecretSchema MakeSchema(byte* packageName, byte* serviceField, byte* accountField)
    {
        return new SecretSchema
        {
            name = packageName,
            flags = 0,
            attr0 = new SecretSchemaAttribute { name = serviceField, type = 0 },
            attr1 = new SecretSchemaAttribute { name = accountField, type = 0 }
        };
    }

    private static void ThrowIfError(IntPtr errorPtr, bool condition, string message)
    {
        if (errorPtr == IntPtr.Zero && !condition) return;
        var errorMessage = errorPtr != IntPtr.Zero ? ReadError(errorPtr) : message;
        throw new InvalidOperationException(errorMessage);
    }

    private static string ReadError(IntPtr err)
    {
        if (err == IntPtr.Zero) return "Unknown error";
        try
        {
            var gerr = *(GError*)err;
            var msg = Marshal.PtrToStringUTF8((IntPtr)gerr.message);
            return $"{msg} (code {gerr.code})";
        }
        catch
        {
            return "Failed to read error details";
        }
    }

    private struct Utf8StringHandle : IDisposable
    {
        public byte[] Buffer { get; }

        private Utf8StringHandle(byte[] buffer) => Buffer = buffer;

        public static Utf8StringHandle Create(string value)
        {
            if (string.IsNullOrEmpty(value))
                return new Utf8StringHandle(new byte[1]);

            var byteCount = Encoding.UTF8.GetByteCount(value);
            var buffer = new byte[byteCount + 1];
            Encoding.UTF8.GetBytes(value, buffer);
            return new Utf8StringHandle(buffer);
        }

        public void Dispose() { }
    }

    [LibraryImport(LibSecret)]
    private static partial IntPtr secret_service_get_sync(uint flags, IntPtr cancellable, out IntPtr error);

    [LibraryImport(LibSecret)]
    private static partial int secret_password_store_sync(
        SecretSchema* schema, byte* collection, byte* label,
        byte* password, IntPtr cancellable, out IntPtr error,
        byte* attr1Name, byte* attr1Value,
        byte* attr2Name, byte* attr2Value,
        IntPtr terminator);

    [LibraryImport(LibSecret)]
    private static partial IntPtr secret_password_lookup_sync(
        SecretSchema* schema, IntPtr cancellable, out IntPtr error,
        byte* attr1Name, byte* attr1Value,
        byte* attr2Name, byte* attr2Value,
        IntPtr terminator);

    [LibraryImport(LibSecret)]
    private static partial int secret_password_clear_sync(
        SecretSchema* schema, IntPtr cancellable, out IntPtr error,
        byte* attr1Name, byte* attr1Value,
        byte* attr2Name, byte* attr2Value,
        IntPtr terminator);

    [LibraryImport(LibSecret)]
    private static partial void secret_password_free(IntPtr password);

    [LibraryImport(LibGObject)]
    private static partial void g_object_unref(IntPtr obj);

    [LibraryImport(LibGlib)]
    private static partial void g_error_free(IntPtr error);

    [StructLayout(LayoutKind.Sequential)]
    private struct SecretSchemaAttribute
    {
        public byte* name;
        public int type;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecretSchema
    {
        public byte* name;
        public int flags;
        public SecretSchemaAttribute attr0;
        public SecretSchemaAttribute attr1;
        public SecretSchemaAttribute attr2;
        public SecretSchemaAttribute attr3;
        public SecretSchemaAttribute attr4;
        public SecretSchemaAttribute attr5;
        public SecretSchemaAttribute attr6;
        public SecretSchemaAttribute attr7;
        public SecretSchemaAttribute attr8;
        public SecretSchemaAttribute attr9;
        public SecretSchemaAttribute attr10;
        public SecretSchemaAttribute attr11;
        public SecretSchemaAttribute attr12;
        public SecretSchemaAttribute attr13;
        public SecretSchemaAttribute attr14;
        public SecretSchemaAttribute attr15;
        public SecretSchemaAttribute attr16;
        public SecretSchemaAttribute attr17;
        public SecretSchemaAttribute attr18;
        public SecretSchemaAttribute attr19;
        public SecretSchemaAttribute attr20;
        public SecretSchemaAttribute attr21;
        public SecretSchemaAttribute attr22;
        public SecretSchemaAttribute attr23;
        public SecretSchemaAttribute attr24;
        public SecretSchemaAttribute attr25;
        public SecretSchemaAttribute attr26;
        public SecretSchemaAttribute attr27;
        public SecretSchemaAttribute attr28;
        public SecretSchemaAttribute attr29;
        public SecretSchemaAttribute attr30;
        public SecretSchemaAttribute attr31;
        public int reserved;
        public void* reserved1;
        public void* reserved2;
        public void* reserved3;
        public void* reserved4;
        public void* reserved5;
        public void* reserved6;
        public void* reserved7;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct GError
    {
        public uint domain;
        public int code;
        public byte* message;
    }
}

// using System.Runtime.InteropServices;
// using System.Text;
// using NativeSecrets.Abstractions;
//
// namespace NativeSecrets.Platforms;
//
// internal sealed unsafe partial class LinuxKeychain : IKeychainStore, IDisposable
// {
//     private const string LibSecret = "libsecret-1.so.0";
//     private const string LibGlib = "libglib-2.0.so.0";
//     private const string LibGObject = "libgobject-2.0.so.0";
//
//     private static readonly byte[] CollectionDefault = [.. "default\0"u8];
//     private static readonly byte[] ServiceFieldName = [.. "service\0"u8];
//     private static readonly byte[] AccountFieldName = [.. "username\0"u8];
//
//     private bool _disposed;
//
//     public bool IsAvailable()
//     {
//         if (_disposed) throw new ObjectDisposedException(nameof(LinuxKeychain));
//
//         var err = IntPtr.Zero;
//         var service = IntPtr.Zero;
//
//         try
//         {
//             service = secret_service_get_sync(0, IntPtr.Zero, out err);
//             
//             if (err != IntPtr.Zero)
//                 return false;
//
//             return service != IntPtr.Zero;
//         }
//         finally
//         {
//             if (service != IntPtr.Zero)
//                 g_object_unref(service);
//             
//             if (err != IntPtr.Zero)
//                 g_error_free(err);
//         }
//     }
//
//     public void SetPassword(string package, string service, string user, string password)
//     {
//         ValidateArguments(package, service, password);
//         
//         var labelText = string.IsNullOrEmpty(user) ? service : $"{service} ({user})";
//
//         using var pkgHandle = Utf8StringHandle.Create(package);
//         using var svcHandle = Utf8StringHandle.Create(service);
//         using var usrHandle = Utf8StringHandle.Create(user);
//         using var pwdHandle = Utf8StringHandle.Create(password);
//         using var lblHandle = Utf8StringHandle.Create(labelText);
//
//         var err = IntPtr.Zero;
//         try
//         {
//             fixed (byte* pPkg = pkgHandle.Span)
//             fixed (byte* pSvc = svcHandle.Span)
//             fixed (byte* pUsr = usrHandle.Span)
//             fixed (byte* pPwd = pwdHandle.Span)
//             fixed (byte* pLbl = lblHandle.Span)
//             fixed (byte* pCol = CollectionDefault)
//             fixed (byte* pFieldSvc = ServiceFieldName)
//             fixed (byte* pFieldAcc = AccountFieldName)
//             {
//                 var schema = MakeSchema(pPkg, pFieldSvc, pFieldAcc);
//
//                 var ok = secret_password_store_sync(
//                     &schema,
//                     pCol,
//                     pLbl,
//                     pPwd,
//                     IntPtr.Zero,
//                     out err,
//                     pFieldSvc, pSvc,
//                     pFieldAcc, pUsr,
//                     IntPtr.Zero);
//
//                 ThrowIfError(err, ok == 0, "secret_password_store_sync failed");
//             }
//         }
//         finally
//         {
//             if (err != IntPtr.Zero)
//                 g_error_free(err);
//         }
//     }
//
//     public string? GetPassword(string package, string service, string? user)
//     {
//         ValidateArguments(package, service);
//
//         using var pkgHandle = Utf8StringHandle.Create(package);
//         using var svcHandle = Utf8StringHandle.Create(service);
//         using var usrHandle = Utf8StringHandle.Create(user ?? string.Empty);
//
//         var err = IntPtr.Zero;
//         var rawPassword = IntPtr.Zero;
//
//         try
//         {
//             fixed (byte* pPkg = pkgHandle.Span)
//             fixed (byte* pSvc = svcHandle.Span)
//             fixed (byte* pUsr = usrHandle.Span)
//             fixed (byte* pFieldSvc = ServiceFieldName)
//             fixed (byte* pFieldAcc = AccountFieldName)
//             {
//                 var schema = MakeSchema(pPkg, pFieldSvc, pFieldAcc);
//
//                 rawPassword = secret_password_lookup_sync(
//                     &schema,
//                     IntPtr.Zero,
//                     out err,
//                     pFieldSvc, pSvc,
//                     pFieldAcc, pUsr,
//                     IntPtr.Zero);
//
//                 ThrowIfError(err, false, "secret_password_lookup_sync failed");
//
//                 return rawPassword == IntPtr.Zero 
//                     ? null 
//                     : Marshal.PtrToStringUTF8(rawPassword);
//             }
//         }
//         finally
//         {
//             if (rawPassword != IntPtr.Zero)
//                 secret_password_free(rawPassword);
//             
//             if (err != IntPtr.Zero)
//                 g_error_free(err);
//         }
//     }
//
//     public bool DeletePassword(string package, string service, string? user)
//     {
//         ValidateArguments(package, service);
//
//         using var pkgHandle = Utf8StringHandle.Create(package);
//         using var svcHandle = Utf8StringHandle.Create(service);
//         using var usrHandle = Utf8StringHandle.Create(user ?? string.Empty);
//
//         var err = IntPtr.Zero;
//         try
//         {
//             fixed (byte* pPkg = pkgHandle.Span)
//             fixed (byte* pSvc = svcHandle.Span)
//             fixed (byte* pUsr = usrHandle.Span)
//             fixed (byte* pFieldSvc = ServiceFieldName)
//             fixed (byte* pFieldAcc = AccountFieldName)
//             {
//                 var schema = MakeSchema(pPkg, pFieldSvc, pFieldAcc);
//
//                 var deleted = secret_password_clear_sync(
//                     &schema,
//                     IntPtr.Zero,
//                     out err,
//                     pFieldSvc, pSvc,
//                     pFieldAcc, pUsr,
//                     IntPtr.Zero);
//
//                 ThrowIfError(err, false, "secret_password_clear_sync failed");
//
//                 return deleted != 0;
//             }
//         }
//         finally
//         {
//             if (err != IntPtr.Zero)
//                 g_error_free(err);
//         }
//     }
//
//     public void Dispose()
//     {
//         if (!_disposed) 
//             _disposed = true;
//     }
//
//     private static void ValidateArguments(string package, string service, string? password = null)
//     {
//         if (string.IsNullOrWhiteSpace(package))
//             throw new ArgumentException("Package name cannot be null or empty", nameof(package));
//         
//         if (string.IsNullOrWhiteSpace(service))
//             throw new ArgumentException("Service name cannot be null or empty", nameof(service));
//         
//         if (password != null && string.IsNullOrEmpty(password))
//             throw new ArgumentException("Password cannot be empty", nameof(password));
//     }
//
//     private static SecretSchema MakeSchema(byte* packageName, byte* serviceField, byte* accountField)
//     {
//         return new SecretSchema
//         {
//             name = packageName,
//             flags = 0, // SECRET_SCHEMA_NONE
//             attr0 = new SecretSchemaAttribute { name = serviceField, type = 0 }, // SECRET_SCHEMA_ATTRIBUTE_STRING
//             attr1 = new SecretSchemaAttribute { name = accountField, type = 0 }
//             // Остальные атрибуты автоматически инициализируются как default (NULL, 0)
//         };
//     }
//
//     private static void ThrowIfError(IntPtr errorPtr, bool condition, string message)
//     {
//         if (errorPtr == IntPtr.Zero && !condition)
//             return;
//         
//         var errorMessage = errorPtr != IntPtr.Zero ? ReadError(errorPtr) : message;
//         throw new InvalidOperationException(errorMessage);
//     }
//
//     private static string ReadError(IntPtr err)
//     {
//         if (err == IntPtr.Zero) 
//             return "Unknown error";
//
//         try
//         {
//             var gerr = *(GError*)err;
//             var msg = Marshal.PtrToStringUTF8((IntPtr)gerr.message);
//             return $"{msg} (code {gerr.code})";
//         }
//         catch
//         {
//             return "Failed to read error details";
//         }
//     }
//
//     // Helper класс для безопасной работы с UTF-8 строками
//     private struct Utf8StringHandle : IDisposable
//     {
//         private readonly byte[] _buffer;
//         private GCHandle _handle;
//
//         public ReadOnlySpan<byte> Span => _buffer;
//
//         private Utf8StringHandle(byte[] buffer, GCHandle handle)
//         {
//             _buffer = buffer;
//             _handle = handle;
//         }
//
//         public static Utf8StringHandle Create(string value)
//         {
//             if (string.IsNullOrEmpty(value))
//             {
//                 var emptyBuffer = new byte[1]; // только нулевой терминатор
//                 return new Utf8StringHandle(emptyBuffer, default);
//             }
//
//             var byteCount = Encoding.UTF8.GetByteCount(value);
//             var buffer = new byte[byteCount + 1];
//             Encoding.UTF8.GetBytes(value, buffer);
//             // Последний байт уже 0 по умолчанию
//
//             return new Utf8StringHandle(buffer, default);
//         }
//
//         public void Dispose()
//         {
//             if (_handle.IsAllocated)
//                 _handle.Free();
//         }
//     }
//
//     [LibraryImport(LibSecret)]
//     private static partial IntPtr secret_service_get_sync(uint flags, IntPtr cancellable, out IntPtr error);
//
//     [LibraryImport(LibSecret)]
//     private static partial int secret_password_store_sync(
//         SecretSchema* schema, byte* collection, byte* label,
//         byte* password, IntPtr cancellable, out IntPtr error,
//         byte* attr1Name, byte* attr1Value,
//         byte* attr2Name, byte* attr2Value,
//         IntPtr terminator);
//
//     [LibraryImport(LibSecret)]
//     private static partial IntPtr secret_password_lookup_sync(
//         SecretSchema* schema, IntPtr cancellable, out IntPtr error,
//         byte* attr1Name, byte* attr1Value,
//         byte* attr2Name, byte* attr2Value,
//         IntPtr terminator);
//
//     [LibraryImport(LibSecret)]
//     private static partial int secret_password_clear_sync(
//         SecretSchema* schema, IntPtr cancellable, out IntPtr error,
//         byte* attr1Name, byte* attr1Value,
//         byte* attr2Name, byte* attr2Value,
//         IntPtr terminator);
//
//     [LibraryImport(LibSecret)]
//     private static partial void secret_password_free(IntPtr password);
//
//     [LibraryImport(LibGObject)]
//     private static partial void g_object_unref(IntPtr obj);
//
//     [LibraryImport(LibGlib)]
//     private static partial void g_error_free(IntPtr error);
//
//     [StructLayout(LayoutKind.Sequential)]
//     private struct SecretSchemaAttribute
//     {
//         public byte* name;
//         public int type;
//     }
//
//     [StructLayout(LayoutKind.Sequential)]
//     private struct SecretSchema
//     {
//         public byte* name;
//         public int flags;
//         public SecretSchemaAttribute attr0;
//         public SecretSchemaAttribute attr1;
//         public SecretSchemaAttribute attr2;
//         public SecretSchemaAttribute attr3;
//         public SecretSchemaAttribute attr4;
//         public SecretSchemaAttribute attr5;
//         public SecretSchemaAttribute attr6;
//         public SecretSchemaAttribute attr7;
//         public SecretSchemaAttribute attr8;
//         public SecretSchemaAttribute attr9;
//         public SecretSchemaAttribute attr10;
//         public SecretSchemaAttribute attr11;
//         public SecretSchemaAttribute attr12;
//         public SecretSchemaAttribute attr13;
//         public SecretSchemaAttribute attr14;
//         public SecretSchemaAttribute attr15;
//         public SecretSchemaAttribute attr16;
//         public SecretSchemaAttribute attr17;
//         public SecretSchemaAttribute attr18;
//         public SecretSchemaAttribute attr19;
//         public SecretSchemaAttribute attr20;
//         public SecretSchemaAttribute attr21;
//         public SecretSchemaAttribute attr22;
//         public SecretSchemaAttribute attr23;
//         public SecretSchemaAttribute attr24;
//         public SecretSchemaAttribute attr25;
//         public SecretSchemaAttribute attr26;
//         public SecretSchemaAttribute attr27;
//         public SecretSchemaAttribute attr28;
//         public SecretSchemaAttribute attr29;
//         public SecretSchemaAttribute attr30;
//         public SecretSchemaAttribute attr31;
//         public int reserved;
//         public void* reserved1;
//         public void* reserved2;
//         public void* reserved3;
//         public void* reserved4;
//         public void* reserved5;
//         public void* reserved6;
//         public void* reserved7;
//     }
//
//     [StructLayout(LayoutKind.Sequential)]
//     private struct GError
//     {
//         public uint domain;
//         public int code;
//         public byte* message;
//     }
// }