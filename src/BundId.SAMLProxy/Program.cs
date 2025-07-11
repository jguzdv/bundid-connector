using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using JGUZDV.AspNetCore.Hosting;
using JGUZDV.BundId.SAMLProxy.Endpoints;
using JGUZDV.BundId.SAMLProxy.SAML2.CertificateHandling;
using JGUZDV.BundId.SAMLProxy.SAML2.MetadataHandling;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using BlazorInteractivityModes = JGUZDV.AspNetCore.Hosting.Components.BlazorInteractivityModes;


var builder = JGUZDVHostApplicationBuilder.CreateWebHost(args, BlazorInteractivityModes.DisableBlazor);
var services = builder.Services;


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

services.AddAuthentication(Saml2Constants.AuthenticationScheme)
    .AddCookie(Saml2Constants.AuthenticationScheme, opt =>
    {
        opt.LoginPath = "/saml2/bund-id/auth";
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
services.AddKeyedScoped("Saml2IDP", (sp, key) => sp.GetRequiredService<IOptionsSnapshot<Saml2Configuration>>().Get((string)key));
services.AddOptions<Saml2Configuration>("Saml2IDP")
    .Bind(builder.Configuration.GetSection("Saml2:IDP"))
    .Configure<IConfiguration>((saml2, config) =>
    {
        saml2.Issuer = config.GetValue<string>("Saml2:EntityId") ?? throw new InvalidOperationException("Saml2:IDP:EntityId is not configured.");
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
