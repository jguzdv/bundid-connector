using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Services;

namespace JGUZDV.BundId.SAMLProxy.SustainsysExt
{
    public class BundIdIdentityProviderConfigurationResolver(IMetadadataLoader metadadataLoader) 
        : IdentityProviderConfigurationResolver(metadadataLoader)
    {
        protected override Task ResolveEffectiveConfigurationAsync(IdentityProviderConfigurationResolverContext context, MetadataBase? metadata)
        {
            if (metadata is EntitiesDescriptor entitiesDescriptor and { EntityDescriptors.Count: 1 })
            {
                metadata = entitiesDescriptor.EntityDescriptors.Single();
            }

            return base.ResolveEffectiveConfigurationAsync(context, metadata);
        }
    }
}
