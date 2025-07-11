
namespace JGUZDV.BundId.SAMLProxy.SAML2.MetadataHandling
{
    internal class MetadataSources
    {
        public List<MetadataDescriptor> MetadataDescriptors { get; set; } = [];
    }

    internal class MetadataDescriptor
    {
        public EntityType EntityType { get; set; } = EntityType.RelyingParty;
        
        public required string MetadataUrl { get; set; }
        public required string EntityId { get; set; }

        public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromHours(1);
    }

    public enum EntityType
    {
        RelyingParty,
        IdentityProvider
    }
}