namespace JGUZDV.BundId.SAMLProxy.ActiveDirectory.Extensions;

public static class BundIdActiveDirectoryExtensions
{
    public static IServiceCollection AddBundIdActiveDirectoryServices(
        this IServiceCollection services, 
        string configSectionName) 
    {
        services.AddOptions<ActiveDirectoryOptions>()
            .BindConfiguration(configSectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddScoped<ActiveDirectoryService>();

        return services;
    }
}
