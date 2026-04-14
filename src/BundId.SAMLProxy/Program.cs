using JGUZDV.AspNetCore.Hosting;
using JGUZDV.BundId.SAMLProxy.Endpoints;
using JGUZDV.BundId.SAMLProxy.SAML2;
using JGUZDV.BundId.SAMLProxy.SAML2.CertificateHandling;
using JGUZDV.BundId.SAMLProxy.SAML2.MetadataHandling;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Sustainsys.Saml2;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Saml2P;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml.Linq;
using BlazorInteractivityModes = JGUZDV.AspNetCore.Hosting.Components.BlazorInteractivityModes;

var builder = JGUZDVHostApplicationBuilder.CreateWebHost(args, BlazorInteractivityModes.DisableBlazor);
var services = builder.Services;

#if DEBUG
Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
#endif

services.AddHttpClient();
services.AddTransient((sp) => TimeProvider.System);

//TODO: This is a redo, since it's missing from the HostBuilder
services.AddRazorPages()
    .AddViewLocalization();

services.Configure<RazorPagesOptions>(opt =>
{
    opt.Conventions.AuthorizePage("/Info");
});


services.AddSession();

services.AddAuthentication(opt =>
{
    opt.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    opt.DefaultChallengeScheme = Saml2Defaults.Scheme;
})
    .AddCookie()
    .AddSaml2(opt =>
    {
        var spEntityId = builder.Configuration["SAML2:EntityId"]
            ?? throw new ArgumentNullException("SAML2:EntityId");
        var bundIdEntityId = builder.Configuration["SAML2:BundId:EntityId"]
            ?? throw new ArgumentNullException("SAML2:BundId:EntityId");

        var certificates = LoadCertificate(builder.Configuration);
        foreach (var cert in certificates)
        {
            opt.SPOptions.ServiceCertificates.Add(cert);
        }

        opt.SPOptions.EntityId = new EntityId(spEntityId);
        
        opt.SPOptions.ModulePath = "/saml2/bund-id";
        opt.SPOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Always;

        opt.SPOptions.Compatibility.UnpackEntitiesDescriptorInIdentityProviderMetadata = true;
        opt.SPOptions.Compatibility.IgnoreAuthenticationContextInResponse = true;

        opt.IdentityProviders.Add(new IdentityProvider(
            new EntityId(bundIdEntityId),
            opt.SPOptions
            )
        {
            LoadMetadata = true,
        });

        opt.Notifications.AuthenticationRequestCreated += OnAuthenticationRequestCreated;
    })
    .AddCookieDistributedTicketStore();

services.AddAuthorizationCore();

services.AddOptions<CertificateOptions>()
    .Bind(builder.Configuration.GetSection("Saml2"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

// Certificate management
services.AddSingleton<CertificateContainer>();
services.AddHostedService<CertificateManager>();

// Creates options e.g. for "/metadata". Creation and post configuration (PostConfigure) happens scoped on every request!
services.AddKeyedScoped("Saml2IDP", (sp, key) => sp.GetRequiredService<IOptionsSnapshot<ITfoxtec.Identity.Saml2.Saml2Configuration>>().Get((string)key));
services.AddOptions<ITfoxtec.Identity.Saml2.Saml2Configuration>("Saml2IDP")
    .Bind(builder.Configuration.GetSection("Saml2:IDP"))
    .Configure<IConfiguration>((saml2, config) =>
    {
        // BundID needs the request to be signed
        saml2.SignAuthnRequest = true;
    })
    .PostConfigure<CertificateContainer>((saml2, certificateContainer) =>
    {
        saml2.AllowedAudienceUris.Add(saml2.Issuer);

        saml2.DecryptionCertificates.AddRange(certificateContainer.GetCertificates());
        saml2.SigningCertificate = certificateContainer.GetSignatureCertificate();
    });

services.AddKeyedScoped("BundId:EntityId", (sp, key) => 
    sp.GetRequiredService<IOptionsSnapshot<MetadataSources>>().Value.MetadataDescriptors
        .SingleOrDefault(x => x.EntityType == EntityType.IdentityProvider)
        ?.EntityId
        ?? throw new InvalidOperationException("No IdentityProvider found in Saml2:MetadataSources.")
);

// Metadata management
services.AddOptions<MetadataSources>()
    .Configure(opt => {
        builder.Configuration.GetSection("Saml2:MetadataSources").Bind(opt.MetadataDescriptors);
    })
    .ValidateDataAnnotations()
    .ValidateOnStart();

services.AddSingleton<MetadataContainer>();
services.AddHostedService<MetadataManager>();



var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    //app.UseStatusCodePagesWithReExecute("/Error/{0}");
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseSession();

app.UseRequestLocalization();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.MapRazorPages();
app.MapBundIdEndpoints();
app.MapSAMLEndpoints();

app.Run();


List<X509Certificate2> LoadCertificate(ConfigurationManager configuration)
{
    var certPath = configuration["Saml2:CertificatesPath"]
        ?? throw new ArgumentNullException("Saml2:CertificatesPath");

    var certPassword = configuration["Saml2:CertificatePassword"];

    var result = new List<X509Certificate2>();

    foreach (var certFile in Directory.GetFiles(certPath, "*.pfx"))
    {
        try
        {
            var cert = X509CertificateLoader.LoadPkcs12FromFile(certFile, certPassword);
            result.Add(cert);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to load certificate from {certFile}.", ex);
        }
    }

    return result.FindAll(cert => cert != null && cert.HasPrivateKey && cert.NotAfter > DateTimeOffset.UtcNow);
}

void OnAuthenticationRequestCreated(Saml2AuthenticationRequest request, IdentityProvider provider, IDictionary<string, string> dictionary)
{
    request.ExtensionContents.Add(XElement.Parse(
    $"""
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
                <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.PersonalTitle}" RequiredAttribute="false" />
                <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.GivenName}" RequiredAttribute="false" />
                <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.Surname}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.Birthdate}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.BirthName}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.PlaceOfBirth}" RequiredAttribute="false" />
                <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.PostalCode}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.LocalityName}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.PostalAddress}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.Country}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.Nationality}" RequiredAttribute="false" />
                <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.Mail}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="urn:oid:{BundIdAttributes.EIDCitizenQaaLevel}" RequiredAttribute="false" />
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
        """
    ));
}