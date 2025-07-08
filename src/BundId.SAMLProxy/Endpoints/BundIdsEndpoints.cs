using ITfoxtec.Identity.Saml2;

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
                .WithName(nameof(InitBundIdAuth))
                .RequireAuthorization();

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

            var samlAuthNRequest = new Saml2AuthnRequest(samlConfig)
            {
                Issuer = "",
            };

            binding.Bind(samlAuthNRequest);
            return Results.Redirect(binding.RedirectLocation.OriginalString);
        }


        //[Route("/saml2/login"), HttpGet]
        //public IActionResult Login(string? returnUrl,
        //[FromServices] Saml2Configuration samlConfig)
        //{
        //    var binding = new Saml2RedirectBinding();
        //    binding.SetRelayStateQuery(
        //        new Dictionary<string, string>
        //        {
        //        { _relayStateReturnUrl, returnUrl ?? Url.Content("~/") }
        //        }
        //    );

        //    var samlAuthnRequest = new Saml2AuthnRequest(samlConfig);
        //    samlAuthnRequest.Issuer = GetEntityId();
        //    return binding.Bind(samlAuthnRequest).ToActionResult();
        //}

        //[Route("/saml2/redirect/post"), HttpPost]
        //public async Task<IActionResult> PostBinding(
        //    [FromServices] Saml2Configuration samlConfig)
        //{
        //    var httpRequest = Request.ToGenericHttpRequest(validate: true);
        //    var saml2AuthnResponse = new Saml2AuthnResponse(samlConfig);

        //    httpRequest.Binding.ReadSamlResponse(httpRequest, saml2AuthnResponse);
        //    if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
        //    {
        //        throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
        //    }
        //    httpRequest.Binding.Unbind(httpRequest, saml2AuthnResponse);
        //    await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: ClaimsTransform.Transform);

        //    var relayStateQuery = httpRequest.Binding.GetRelayStateQuery();
        //    relayStateQuery.TryGetValue(_relayStateReturnUrl, out var returnUrl);
        //    returnUrl ??= Url.Content("~/");

        //    return Redirect(returnUrl);
        //}
    }
}
