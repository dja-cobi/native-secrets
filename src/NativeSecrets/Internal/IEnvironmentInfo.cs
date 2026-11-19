namespace NativeSecrets.Internal;

/// <summary>Abstraction over <see cref="Environment"/> for testability.</summary>
internal interface IEnvironmentInfo
{
    /// <summary>Machine name.</summary>
    string MachineName { get; }

    /// <summary>Current username.</summary>
    string UserName { get; }

    /// <summary>Best-effort stable device identifier.</summary>
    string GetDeviceId();
}