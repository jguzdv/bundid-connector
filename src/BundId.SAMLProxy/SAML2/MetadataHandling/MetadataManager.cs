
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.Extensions.Options;

namespace JGUZDV.BundId.SAMLProxy.SAML2.MetadataHandling;


/// <summary>
/// This manager/hosted service is used to update the EntityDescriptor's for all
/// known/configured RelyingParties every hour. A table of timers (scheduled executors)
/// is used to repeat the fetch process for every known EntityId.
/// </summary>
internal class MetadataManager : IHostedService
{
    private readonly CancellationTokenSource _cancellationTokenSource = new();
    private readonly List<PeriodicTimer> _timers = [];

    
    // Our metadata container where we need to replace the entries every hour.
    private readonly MetadataContainer _metadataContainer;

    // The options contain the list of known relying parties to update.
    private readonly IOptions<MetadataSources> _options;

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<MetadataManager> _logger;

    public MetadataManager(
        MetadataContainer metadataContainer,
        IHttpClientFactory httpClientFactory,
        IOptions<MetadataSources> options,
        ILogger<MetadataManager> logger)
    {
        _metadataContainer = metadataContainer;
        _httpClientFactory = httpClientFactory;
        _options = options;
        _logger = logger;

    }


    /// <summary>
    /// Start timers (scheduled executors) to update metadata for all known relying parties regularly.
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        foreach (var entry in _options.Value.MetadataDescriptors)
        {
            InitializeMetadataSource(entry);
        }

        return Task.CompletedTask;
    }


    public void InitializeMetadataSource(MetadataDescriptor entry)
    {
        var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(1));
        _timers.Add(timer);

        _ = PeriodicallyReloadMetadata(entry, timer);
    }

    /// <summary>
    /// Reload and set/replace an EntityDescriptor in the MetadataContainer.
    /// Note: We do not reuse the asynchronous mechanic from the MetadataContainer built around
    /// GetByEntityId(...) and LoadMetadataAsync:
    /// 1) We want to catch read errors here, and do nothing further than log the error, but do not replace the current entry.
    /// 2) We must run into the LoadMetadataAsync exception handling block that remove's our current EntityDescriptor entry.
    /// </summary>
    /// <param name="option"></param>
    /// <returns></returns>
    private async Task PeriodicallyReloadMetadata(MetadataDescriptor entry, PeriodicTimer timer)
    {
        while (await timer.WaitForNextTickAsync(_cancellationTokenSource.Token))
        {
            try
            {
                var entityDescriptor = new EntityDescriptor();

                var entityDescriptorLoader = entry.EntityType switch
                {
                    EntityType.IdentityProvider => entityDescriptor.ReadIdPSsoDescriptorFromUrlAsync(_httpClientFactory, new Uri(entry.MetadataUrl), _cancellationTokenSource.Token),
                    EntityType.RelyingParty => entityDescriptor.ReadSPSsoDescriptorFromUrlAsync(_httpClientFactory, new Uri(entry.MetadataUrl), _cancellationTokenSource.Token),
                    _ => throw new InvalidOperationException($"Unknown EntityType {entry.EntityType} for entry {entry.EntityId}")
                };

                entityDescriptor = await entityDescriptorLoader;
                timer.Period = entry.RefreshInterval;

                _metadataContainer.AddOrReplace(entry.EntityId, entityDescriptor);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unable to load and exchange metadata for entry {entityId} from {url}", entry.EntityId, entry.MetadataUrl);
                timer.Period = TimeSpan.FromSeconds(15); // Retry more often in case of an error.
            }
        }


        
    }


    public Task StopAsync(CancellationToken cancellationToken)
    {
        foreach (var timer in _timers)
        {
            timer.Dispose();
        }

        return Task.CompletedTask;
    }
}
