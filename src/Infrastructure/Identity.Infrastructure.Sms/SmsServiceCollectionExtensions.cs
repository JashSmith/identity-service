using Identity.Application.Sms;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Identity.Infrastructure.Sms;

public static class SmsServiceCollectionExtensions
{
    /// <summary>The providers shipped with the gateway: Kavenegar and the development (recording) provider.</summary>
    public static IServiceCollection AddBuiltInSmsProviders(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        // The Kavenegar URL contains the API key: no request logging for this client.
        services.AddHttpClient(KavenegarSmsProvider.HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(15)).RemoveAllLoggers();
        services.AddSmsProvider<KavenegarSmsProvider>();
        services.AddSingleton<DevelopmentSmsProvider>();
        services.AddSingleton<ISmsProvider>(sp => sp.GetRequiredService<DevelopmentSmsProvider>());
        services.AddSingleton<ISmsOutbox>(sp => sp.GetRequiredService<DevelopmentSmsProvider>());
        return services;
    }

    /// <summary>Registers another provider; the console lists it and builds its settings form from its fields.</summary>
    public static IServiceCollection AddSmsProvider<TProvider>(this IServiceCollection services) where TProvider : class, ISmsProvider
    {
        services.AddSingleton<TProvider>();
        services.AddSingleton<ISmsProvider>(sp => sp.GetRequiredService<TProvider>());
        return services;
    }
}
