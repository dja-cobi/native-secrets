namespace NativeSecrets.Internal;

/// <summary>Default implementation backed by <see cref="Environment"/>.</summary>
internal sealed class DefaultEnvironmentInfo : IEnvironmentInfo
{
    /// <inheritdoc />
    public string MachineName => Environment.MachineName;
    /// <inheritdoc />
    public string UserName => Environment.UserName;
    /// <inheritdoc />
    public string GetDeviceId()
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
                return Environment.GetEnvironmentVariable("IOPlatformUUID") ?? "mac";
            }
            else if (OperatingSystem.IsWindows())
            {
                try
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine
                        .OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
                    if (key?.GetValue("MachineGuid") is string guid && !string.IsNullOrWhiteSpace(guid))
                        return guid;
                }
                catch
                {
                    // ignored
                }

                return "win";
            }
        }
        catch
        {
            // ignored
        }

        return "unknown";
    }
}