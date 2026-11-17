namespace NativeSecrets;

/// <summary>
/// Configuration options for <see cref="NativeSecretsProvider"/>.
/// </summary>
public class NativeSecretsOptions
{
    /// <summary>
    /// Gets or sets the default package or application identifier used when storing credentials in the OS keyring.
    /// Defaults to <c>"NativeSecretsApp"</c>.
    /// </summary>
    public string DefaultService { get; init; } = "NativeSecretsApp";
}