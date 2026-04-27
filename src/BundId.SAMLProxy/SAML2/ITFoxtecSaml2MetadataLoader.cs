using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using JGUZDV.Extensions.SAML2.Metadata;

namespace JGUZDV.BundId.SAMLProxy.SAML2
{
    public class ITFoxtecSaml2MetadataLoader(IHttpClientFactory httpClientFactory) : MetadataLoader<EntityDescriptor>
    {
        private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;

        public override async Task<EntityDescriptor> LoadMetadataAsync(RelyingPartyEntry entry)
        {
            var entityDescriptor = new EntityDescriptor();
            
            try
            {
                await entityDescriptor.ReadSPSsoDescriptorFromUrlAsync(_httpClientFactory, new Uri(entry.MetadataUrl));
                return entityDescriptor;
            }
            catch (Exception ex)
            {
                throw new MetadataLoaderException($"Error loading metadata for entityId {entry.EntityId} from url {entry.MetadataUrl}", ex);
            }
        }
    }
}
