using JGUZDV.AspNetCore.Hosting;
using JGUZDV.BundId.SAMLProxy.Endpoints;
using JGUZDV.BundId.SAMLProxy.SAML2;
using JGUZDV.Extensions.SAML2.Certificates;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Sustainsys.Saml2;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
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
    .AddCookie(opt =>
    {
        if(builder.Environment.IsDevelopment())
        {
            opt.ExpireTimeSpan = TimeSpan.FromMinutes(1);
        }

        opt.ExpireTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddSaml2(opt =>
    {
        var spEntityId = builder.Configuration["SAML2:EntityId"]
            ?? throw new ArgumentNullException("SAML2:EntityId");
        var bundIdEntityId = builder.Configuration["SAML2:BundId:EntityId"]
            ?? throw new ArgumentNullException("SAML2:BundId:EntityId");

        var certificates = BundIDHelpers.LoadCertificate(builder.Configuration);
        foreach (var cert in certificates)
        {
            opt.SPOptions.ServiceCertificates.Add(cert);
        }

        opt.SPOptions.EntityId = new EntityId(spEntityId);

        opt.SPOptions.ModulePath = "/saml2/bund-id/post";
        opt.SPOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Always;

        opt.SPOptions.Compatibility.UnpackEntitiesDescriptorInIdentityProviderMetadata = true;
        opt.SPOptions.Compatibility.IgnoreAuthenticationContextInResponse = true;

        opt.IdentityProviders.Add(
            new IdentityProvider(
                new EntityId(bundIdEntityId),
                opt.SPOptions
            )
            {
                LoadMetadata = true,
            });

        opt.Notifications.AuthenticationRequestCreated += BundIDHelpers.OnAuthenticationRequestCreated;
        opt.Notifications.AcsCommandResultCreated += BundIDHelpers.OnAcsCommandResultCreated;
    })
    .AddCookieDistributedTicketStore();

services.AddAuthorizationCore();


// Creates options e.g. for "/metadata". Creation and post configuration (PostConfigure) happens scoped on every request!
services.AddKeyedScoped("Saml2IDP", (sp, key) => sp.GetRequiredService<IOptionsSnapshot<ITfoxtec.Identity.Saml2.Saml2Configuration>>().Get((string)key));
services.AddOptions<ITfoxtec.Identity.Saml2.Saml2Configuration>("Saml2IDP")
    .Bind(builder.Configuration.GetSection("SAML2:IDP"))
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


services.AddSaml2MetadataManager<ITfoxtec.Identity.Saml2.Schemas.Metadata.EntityDescriptor, ITFoxtecSaml2MetadataLoader>()
    .BindConfiguration("SAML2:IDP")
    .ValidateDataAnnotations()
    .ValidateOnStart();

services.AddSaml2CertificateManager();
services.AddOptions<CertificateOptions>()
    .Bind(builder.Configuration.GetSection("SAML2:IDP"))
    .ValidateDataAnnotations()
    .ValidateOnStart();


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
//app.MapBundIdEndpoints();
app.MapSAMLEndpoints();

app.Run();