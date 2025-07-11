using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using System.Security.Authentication;

namespace JGUZDV.BundId.SAMLProxy.Endpoints
{
    public static class BundIdsEndpoints
    {
        public static IEndpointRouteBuilder MapBundIdEndpoints(this IEndpointRouteBuilder endpoints)
        {
            var saml = endpoints.MapGroup("saml2");
            saml.WithTags("SAML2");

            var idp = saml.MapGroup("bund-id");

            idp.MapGet("/auth", InitBundIdAuth)
                .WithName(EndpointNames.BundIdAuthenticate);
            //idp.MapPost("/auth", SignInBundId)
            //    .WithName(nameof(SignInBundId));

            endpoints.MapPost("saml2/post", SignInBundId)
                .WithName(nameof(SignInBundId));

            return endpoints;
        }


        public static IResult InitBundIdAuth(
            HttpContext context,
            LinkGenerator linkGenerator,
            string returnUrl,
            Saml2Configuration samlConfig)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(
                new Dictionary<string, string>
                {
                    { "returnUrl", returnUrl ?? "/" }
                }
            );

            // TODO: Read from Config / Metadata
            var samlAuthNRequest = new Saml2AuthnRequest(samlConfig)
            {
                Issuer = "https://bundid.uni-mainz.de",
                Destination = new Uri("https://int.id.bund.de/idp/profile/SAML2/Redirect/SSO"),
            };

            binding.Bind(samlAuthNRequest);
            return Results.Redirect(binding.RedirectLocation.OriginalString);
        }


        public static async Task<IResult> SignInBundId(
            HttpContext context,
            Saml2Configuration samlConfig
            )
        {
            var httpRequest = context.Request.ToGenericHttpRequest(validate: true);
            var saml2AuthnResponse = new Saml2AuthnResponse(samlConfig);

            httpRequest.Binding.ReadSamlResponse(httpRequest, saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }

            httpRequest.Binding.Unbind(httpRequest, saml2AuthnResponse);
            await saml2AuthnResponse.CreateSession(context, claimsTransform: ClaimsTransform.Transform);

            var relayStateQuery = httpRequest.Binding.GetRelayStateQuery();
            relayStateQuery.TryGetValue("returnUrl", out var returnUrl);

            return Results.Redirect(returnUrl);
        }
    }
}
