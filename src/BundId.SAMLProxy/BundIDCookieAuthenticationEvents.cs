using JGUZDV.ActiveDirectory.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace JGUZDV.BundId.SAMLProxy;

public class BundIDCookieAuthenticationEvents : CookieAuthenticationEvents
{
    private readonly IClaimProvider _claimProvider;

    public BundIDCookieAuthenticationEvents(IClaimProvider claimProvider)
    {
        _claimProvider = claimProvider;
    }

    public override async Task SigningIn(CookieSigningInContext context)
    {


        _claimProvider.GetClaims();
    }
}
