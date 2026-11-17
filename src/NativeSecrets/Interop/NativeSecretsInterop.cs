using System.Reflection;
using System.Runtime.InteropServices;

namespace NativeSecrets.Interop;

internal static partial class NativeSecretsInterop
{
    private const string Lib = "skeychain";

    static NativeSecretsInterop() => 
        NativeLibrary.SetDllImportResolver(typeof(NativeSecretsInterop).Assembly, ResolveNativeLibrary);

    private static IntPtr ResolveNativeLibrary(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != Lib) return IntPtr.Zero;

        if (NativeLibrary.TryLoad(libraryName, assembly, searchPath, out var handle))
            return handle;

        var arch = RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant();
        var folder = OperatingSystem.IsLinux() ? $"linux-{arch}" :
            OperatingSystem.IsWindows() ? $"win-{arch}" :
            OperatingSystem.IsMacOS() ? $"osx-{arch}" : "";

        var fileName = OperatingSystem.IsWindows() ? "skeychain.dll" :
            OperatingSystem.IsMacOS() ? "libskeychain.dylib" : "libskeychain.so";

        var path = Path.Combine(AppContext.BaseDirectory, "runtimes", folder, "native", fileName);

        if (File.Exists(path) && NativeLibrary.TryLoad(path, out handle))
            return handle;

        return IntPtr.Zero;
    }

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8, EntryPoint = "setPassword")]
    internal static partial void SetPassword(string package, string service, string user, string password);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8, EntryPoint = "getPassword")]
    internal static partial IntPtr GetPassword(string package, string service, string user);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8, EntryPoint = "deletePassword")]
    internal static partial void DeletePassword(string package, string service, string user);

    [LibraryImport(Lib, EntryPoint = "getLastError")]
    internal static partial int GetLastError();

    [LibraryImport(Lib, EntryPoint = "getLastErrorMessage")]
    internal static partial IntPtr GetLastErrorMessage();
}