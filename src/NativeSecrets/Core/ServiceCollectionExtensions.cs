using NativeSecrets.Abstractions;
#if !NETSTANDARD2_0
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
#endif

namespace NativeSecrets.Core;

#if !NETSTANDARD2_0
public static class ServiceCollectionExtensions
{
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
#endif
