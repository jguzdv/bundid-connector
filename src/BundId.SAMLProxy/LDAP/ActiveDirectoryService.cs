using Microsoft.Extensions.Options;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.Versioning;

namespace JGUZDV.BundId.SAMLProxy.ActiveDirectory;

[SupportedOSPlatform("windows")]
public class ActiveDirectoryService
{
    private readonly IOptions<ActiveDirectoryOptions> _adOptions;
    private readonly ILogger<ActiveDirectoryService> _logger;

    private List<string>? _ldapServers;
    
    public ActiveDirectoryService(IOptions<ActiveDirectoryOptions> adOptions, ILogger<ActiveDirectoryService> logger)
    {
        _adOptions = adOptions;
        _logger = logger;
    }


    public DirectoryEntry? GetUserFromBundIdBPK2(string bundIdbpk2, string issuer)
    {
        List<SearchResult> userResults;
        try
        {
            userResults = PerformSearchWithRetry(
                _adOptions.Value.BaseOU,
                $"(&(objectClass=user)({_adOptions.Value.BundIdBPK2Property}={bundIdbpk2}@{issuer}))",
                ["distinguishedName", "userPrincipalName", "objectGuid", "eduPersonPrincipalName"],
                SearchScope.Subtree);

        
            if (userResults.Count == 0)
            {
                return null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to search for user with BundIdBPK2 {bundIdbpk2}, on {domain} in {baseOu}", bundIdbpk2, _adOptions.Value.DomainName, _adOptions.Value.BaseOU);
            return null;
        }

        if (userResults.Count > 1)
        {
            _logger.LogError("There where mutliple users found with BundIdBPK2 {bundIdbpk2}", bundIdbpk2);
        }

        return userResults.First().GetDirectoryEntry();
    }


    public bool IsUserAllowedToLogin(DirectoryEntry userEntry, DateTimeOffset refDate)
    {
        const int UF_ACCOUNTDISABLE = 0x0002;
        const int UF_NORMAL_ACCOUNT = 0x0200;
        const int UF_SMARTCARD_REQUIRED = 0x40000;

        userEntry.RefreshCache(["userAccountControl", "accountExpires"]);

        if (userEntry.Properties["userAccountControl"]?.Value is not int userAccountControl)
        {
            _logger.LogError("Failed to read userAccountControl for {userDN}", userEntry.Path);
            return false;
        }

        if ((userAccountControl & UF_ACCOUNTDISABLE) == UF_ACCOUNTDISABLE)
        {
            _logger.LogInformation("User {userDN} is disabled", userEntry.Path);
            return false;
        }

        if ((userAccountControl & UF_SMARTCARD_REQUIRED) == UF_SMARTCARD_REQUIRED)
        {
            _logger.LogInformation("User {userDN} requires smartcard", userEntry.Path);
            return false;
        }

        if ((userAccountControl & UF_NORMAL_ACCOUNT) != UF_NORMAL_ACCOUNT)
        {
            _logger.LogInformation("User {userDN} is not a normal account", userEntry.Path);
            return false;
        }


        if (userEntry.Properties["accountExpires"]?.GetLargeInteger() is not long accountExpires)
        {
            _logger.LogError("Failed to read accountExpires for {userDN}", userEntry.Path);
            return false;
        }

        if (accountExpires != 0 && accountExpires <= refDate.ToFileTime())
        {
            _logger.LogInformation("User {userDN} account has expired", userEntry.Path);
            return false;
        }

        return true;
    }


    private List<string> GetADServers()
    {
        var directoryContext = _adOptions.Value.DomainName != null
            ? new DirectoryContext(DirectoryContextType.Domain, _adOptions.Value.DomainName)
            : new DirectoryContext(DirectoryContextType.Domain);

        var domainController = _adOptions.Value.DomainSite != null
            ? DomainController.FindOne(directoryContext, _adOptions.Value.DomainSite, LocatorOptions.ForceRediscovery)
            : DomainController.FindOne(directoryContext, LocatorOptions.ForceRediscovery);

        if (domainController.Roles.Contains(ActiveDirectoryRole.PdcRole))
        {
            return [domainController.Name];
        }

        var domain = Domain.GetDomain(directoryContext);
        var pdcRoleOwner = domain.PdcRoleOwner;

        return pdcRoleOwner != null
            ? [domainController.Name, pdcRoleOwner.Name]
            : [domainController.Name];
    }

    private List<SearchResult> PerformSearchWithRetry(string basePath, string ldapFilter, string[] propertiesToLoad, SearchScope scope)
    {
        _ldapServers ??= GetADServers();

        for (var i = 0; i < _ldapServers.Count; i++)
        {
            try
            {
                var result = PerformSearch(_ldapServers[i], basePath, ldapFilter, propertiesToLoad, scope);
                if (result.Count > 0)
                {
                    return result;
                }
            }
            catch (DirectoryServicesCOMException ex)
            {
                _logger.LogWarning(ex, "Failed to perform search on {ldapServer} for {basePath} with filter {ldapFilter}. Retrying with next server.", _ldapServers[i], basePath, ldapFilter);
            }
        }

        return [];
    }


    private List<SearchResult> PerformSearch(string ldapServer, string basePath, string ldapFilter, string[] propertiesToLoad, SearchScope scope)
    {
        using var searcher = new DirectorySearcher(
            new DirectoryEntry($"LDAP://{ldapServer}:{_adOptions.Value.LdapPort}/{basePath}"),
            ldapFilter, propertiesToLoad, scope);

        return [.. searcher.FindAll().Cast<SearchResult>()];
    }
}
