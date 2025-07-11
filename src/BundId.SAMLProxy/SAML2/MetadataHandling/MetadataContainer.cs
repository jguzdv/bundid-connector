using ITfoxtec.Identity.Saml2.Schemas.Metadata;

namespace JGUZDV.BundId.SAMLProxy.SAML2.MetadataHandling;

/// <summary>
/// Encapsulates logic/data to handle EntityDescriptor's. An EntityDescriptor describes a
/// SAML IdP or Saml ServiceProvider/RelyingParty. @see https://en.wikipedia.org/wiki/SAML_metadata
/// The property _metadata is used to store EntityDescriptor's. The dictionary uses EntityId's as
/// keys, and takes a Task that determines an EntityDescriptor. We do not store the EntityDescriptor
/// directly, but store the Task that runs asynchronously, so if GetByEntityId(...) is called multiple
/// times, and fetching an EntityDescriptor is not yet completed, all threads wait for the same Task.
/// </summary>
public class MetadataContainer
{
    // Stores EntityId -> Task. The Task tries to fetch an EntityDescriptor for the given EntityId.
    private readonly Dictionary<string, TaskCompletionSource<EntityDescriptor>> _metadataTasks = [];
    private readonly Dictionary<string, EntityDescriptor> _metadata = [];

    private readonly Lock _lock = new();


    public void AddOrReplace(string entityId, EntityDescriptor descriptor)
    {
        lock(_lock)
        {
            if(_metadataTasks.TryGetValue(entityId, out var existing))
            {
                existing.SetResult(descriptor);
            }

            _metadata[entityId] = descriptor;
        }
    }

    /// <summary>
    /// Creates a task to either fetch the currently stored EntityDescriptor, or otherwise to load it.
    /// This mechanic ensures that we try to load an EntityDescriptor before we continue processing
    /// the current authentication request.
    /// </summary>
    /// <param name="entityId">A given entityId (from a saml authentication request)</param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException">When the given entityId is unknown.</exception>
    public Task<EntityDescriptor> GetByEntityId(string entityId)
    {
        lock(_lock)
        {
            if (_metadata.TryGetValue(entityId, out var metadata))
            {
                return Task.FromResult(metadata);
            }

            if (!_metadataTasks.TryGetValue(entityId, out var existingTask))
            {
                existingTask = _metadataTasks[entityId] = new TaskCompletionSource<EntityDescriptor>();
            }

            return existingTask.Task;
        }
    }
}
