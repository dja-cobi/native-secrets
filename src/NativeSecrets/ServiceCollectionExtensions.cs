using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace NativeSecrets;

/// <summary>
/// Extension methods for setting up native OS credential store services in an <see cref="IServiceCollection"/>.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the native secrets provider to the specified <see cref="IServiceCollection"/> using a configuration delegate.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <param name="configure">An optional action to configure <see cref="NativeSecretsOptions"/>.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is <see langword="null"/>.</exception>
    public static IServiceCollection AddNativeSecrets(this IServiceCollection services,
        Action<NativeSecretsOptions>? configure = null)
    {
        var options = new NativeSecretsOptions();
        configure?.Invoke(options);

        services.AddSingleton<INativeSecrets>(new NativeSecretsProvider(options));
        return services;
    }

    /// <summary>
    /// Adds the native secrets provider to the specified <see cref="IServiceCollection"/> using settings from <see cref="IConfiguration"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <param name="configuration">The <see cref="IConfiguration"/> instance containing the settings.</param>
    /// <param name="sectionName">The name of the configuration section to read. Defaults to <c>"NativeSecrets"</c>.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> or <paramref name="configuration"/> is <see langword="null"/>.</exception>
    public static IServiceCollection AddNativeSecrets(this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = "NativeSecrets")
    {
        var section = configuration.GetSection(sectionName);

        var options = new NativeSecretsOptions
        {
            DefaultService = section["DefaultService"] ?? "NativeSecretsApp"
        };

        services.AddSingleton<INativeSecrets>(new NativeSecretsProvider(options));
        return services;
    }
}