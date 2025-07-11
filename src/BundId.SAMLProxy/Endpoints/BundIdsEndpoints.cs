﻿using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using JGUZDV.BundId.SAMLProxy.SAML2.MetadataHandling;
using Microsoft.Extensions.DependencyInjection;
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


        public static async Task<IResult> InitBundIdAuth(
            HttpContext context,
            string returnUrl,
            MetadataContainer metadata,
            LinkGenerator linkGenerator,
            [FromKeyedServices("Saml2IDP")] Saml2Configuration samlConfig,
            [FromKeyedServices("BundId:EntityId")] string upstreamEntityId)
        {
            var entityDescriptor = await metadata.GetByEntityId(upstreamEntityId);

            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(
                new Dictionary<string, string>
                {
                    { "returnUrl", returnUrl ?? "/" }
                }
            );

            // TODO: Read from Config / Metadata
            var samlAuthNRequest = new Saml2AuthnRequest(new())
            {
                Issuer = samlConfig.Issuer,
                Destination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices
                    .First(x => x.Binding == new Uri("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"))
                    .Location,
            };

            binding.Bind(samlAuthNRequest);
            return Results.Redirect(binding.RedirectLocation.OriginalString);
        }


        public static async Task<IResult> SignInBundId(
            HttpContext context,
            [FromKeyedServices("Saml2SP")] Saml2Configuration samlConfig
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
