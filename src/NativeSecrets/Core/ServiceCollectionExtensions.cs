using NativeSecrets.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace NativeSecrets.Core;

/// <summary>DI registration helpers.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers a singleton <see cref="IKeychainStore"/> using <see cref="KeychainFactory.CreateProvider"/>.
    /// </summary>
    public static IServiceCollection AddNativeSecrets(this IServiceCollection services,
        Action<KeychainOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        var options = new KeychainOptions();
        configure?.Invoke(options);
        services.TryAddSingleton<IKeychainStore>(_ => KeychainFactory.CreateProvider(options));
        return services;
    } 
}
