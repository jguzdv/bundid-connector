using JGUZDV.ActiveDirectory.Claims;
using JGUZDV.BundId.SAMLProxy.ActiveDirectory;
using JGUZDV.BundId.SAMLProxy.SAML2;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

namespace JGUZDV.BundId.SAMLProxy;

public class BundIDCookieAuthenticationEvents : CookieAuthenticationEvents
{
    private readonly ActiveDirectoryService _adService;
    private readonly IClaimProvider _claimProvider;

    public BundIDCookieAuthenticationEvents(
        ActiveDirectoryService adService,
        IClaimProvider claimProvider
        )
    {
        _adService = adService;
        _claimProvider = claimProvider;
    }

    public override async Task SigningIn(CookieSigningInContext context)
    {
        if (context.Principal == null)
        {
            return;
        }

        var bpk2 = context.Principal!.Claims.FirstOrDefault(x => x.Type == BundIdAttributes.BPK2)?.Value;
        var issuer = context.Principal.Claims.FirstOrDefault(x => x.Type == "issuer")?.Value;
        if (string.IsNullOrWhiteSpace(bpk2) || string.IsNullOrWhiteSpace(issuer)) {
            throw new InvalidOperationException("BPK2 or issuer claim is missing in the principal.");
        }

        var adUser = _adService.GetUserFromBundIdBPK2(bpk2, issuer);
        if (adUser == null)
        {
            // If we could not map the user, we will not add any claims. The claims will be passed through as is.
            return;
        }

        var providedClaims = _claimProvider.GetClaims(adUser, "upn");
        List<Claim> claims = [
            .. providedClaims.Select(x => new Claim(x.Type, x.Value)),
            .. context.Principal.Claims
        ];

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
        context.Principal = principal;
    }
}
