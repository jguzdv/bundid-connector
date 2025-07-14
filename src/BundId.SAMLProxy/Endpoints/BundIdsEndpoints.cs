using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using JGUZDV.BundId.SAMLProxy.SAML2;
using JGUZDV.BundId.SAMLProxy.SAML2.MetadataHandling;
using Microsoft.Extensions.Caching.Distributed;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Xml.Linq;

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
            IDistributedCache distributedCache,
            MetadataContainer metadata,
            LinkGenerator linkGenerator,
            [FromKeyedServices("Saml2IDP")] Saml2Configuration samlConfig,
            [FromKeyedServices("BundId:EntityId")] string upstreamEntityId,
            CancellationToken ct)
        {
            var entityDescriptor = await metadata.GetByEntityId(upstreamEntityId);

            var relayStateId = await CreateRelayState(returnUrl, distributedCache, ct);

            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new() 
            {
                ["relayStateId"] = relayStateId
            });

            var samlAuthNRequest = new Saml2AuthnRequest(samlConfig)
            {
                Destination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices
                    .First(x => x.Binding == new Uri("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"))
                    .Location,

            };

            samlAuthNRequest.Extensions = new ITfoxtec.Identity.Saml2.Schemas.Extensions();
            samlAuthNRequest.Extensions.Element.Add(
                XElement.Parse($"""
                    <akdb:AuthenticationRequest xmlns:akdb="https://www.akdb.de/request/2018/09" EnableStatusDetail="true" Version="2">
                        <akdb:AuthnMethods>
                            <akdb:Authega><akdb:Enabled>true</akdb:Enabled></akdb:Authega>
                            <akdb:Benutzername><akdb:Enabled>true</akdb:Enabled></akdb:Benutzername>
                            <akdb:Diia><akdb:Enabled>true</akdb:Enabled></akdb:Diia>
                            <akdb:eID><akdb:Enabled>true</akdb:Enabled></akdb:eID>
                            <akdb:eIDAS><akdb:Enabled>true</akdb:Enabled></akdb:eIDAS>
                            <akdb:Elster><akdb:Enabled>true</akdb:Enabled></akdb:Elster>
                            <akdb:FINK><akdb:Enabled>true</akdb:Enabled></akdb:FINK>
                        </akdb:AuthnMethods>
                        <akdb:RequestedAttributes>
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.Gender}" RequiredAttribute="true" />
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.PersonalTitle}" RequiredAttribute="true" />
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.GivenName}" RequiredAttribute="true" />
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.Surname}" RequiredAttribute="true" />
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.Birthdate}" RequiredAttribute="true" />
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.BirthName}" RequiredAttribute="true" />
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.PlaceOfBirth}" RequiredAttribute="true" />
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.PostalCode}" RequiredAttribute="true" />
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.LocalityName}" RequiredAttribute="true" />
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.PostalAddress}" RequiredAttribute="true" />
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.Country}" RequiredAttribute="true" />
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.Nationality}" RequiredAttribute="true" />
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.Mail}" RequiredAttribute="true" />
                            <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.EIDCitizenQaaLevel}" RequiredAttribute="true" />
                        </akdb:RequestedAttributes>
                        <akdb:DisplayInformation>
                            <classic-ui:Version xmlns:classic-ui="https://www.akdb.de/request/2018/09/classic-ui/v1">
                                <classic-ui:OrganizationDisplayName>
                                    <![CDATA[Johannes Gutenberg-Universität Mainz]]>
                                </classic-ui:OrganizationDisplayName>
                                <classic-ui:Lang>de</classic-ui:Lang>
                            </classic-ui:Version>
                        </akdb:DisplayInformation>
                    </akdb:AuthenticationRequest>
                    """)
                );

            binding.Bind(samlAuthNRequest);
            return Results.Redirect(binding.RedirectLocation.OriginalString);
        }

        
        public static async Task<IResult> SignInBundId(
            HttpContext context,
            MetadataContainer metadata,
            LinkGenerator linkGenerator,
            [FromKeyedServices("Saml2IDP")] Saml2Configuration samlConfig,
            [FromKeyedServices("BundId:EntityId")] string upstreamEntityId
            )
        {
            var entityDescriptor = await metadata.GetByEntityId(upstreamEntityId);

            var httpRequest = context.Request.ToGenericHttpRequest(validate: true);
            var saml2AuthnResponse = new Saml2AuthnResponse(samlConfig)
            {
                SignatureValidationCertificates = entityDescriptor.IdPSsoDescriptor.SigningCertificates
            };

            httpRequest.Binding.ReadSamlResponse(httpRequest, saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }

            httpRequest.Binding.Unbind(httpRequest, saml2AuthnResponse);
            await saml2AuthnResponse.CreateSession(context, claimsTransform: ClaimsTransform.Transform);

            var relayStateQuery = httpRequest.Binding.GetRelayStateQuery();
            relayStateQuery.TryGetValue("relayStateId", out var relayStateId);

            var returnUrl = await ReadRelayState(relayStateId, context.RequestServices.GetRequiredService<IDistributedCache>(), context.RequestAborted);

            return Results.Redirect(returnUrl ?? "/Info");
        }


        #region RelayState Helpers

        private static async Task<string> CreateRelayState(string returnUrl, IDistributedCache distributedCache, CancellationToken cancellationToken)
        {
            var relayStateId = new Guid(RandomNumberGenerator.GetBytes(16)).ToString("N");

            await distributedCache.SetStringAsync(
                $"RelayState:{relayStateId}",
                returnUrl,
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30) // Set an expiration time for the relay state
                },
                cancellationToken
            );

            return relayStateId;
        }

        private static Task<string?> ReadRelayState(string? relayStateId, IDistributedCache distributedCache, CancellationToken cancellationToken)
        {
            if (relayStateId is null)
            {
                return Task.FromResult((string?)null);
            }

            return distributedCache.GetStringAsync($"RelayState:{relayStateId}", cancellationToken);
        }

        #endregion
    }
}
