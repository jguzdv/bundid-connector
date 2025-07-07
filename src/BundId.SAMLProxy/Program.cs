
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using JGUZDV.AspNetCore.Hosting;
using JGUZDV.BundId.SAMLProxy.Endpoints;
using JGUZDV.BundId.SAMLProxy.SAML2.CertificateHandling;
using JGUZDV.BundId.SAMLProxy.SAML2.MetadataHandling;
using Microsoft.AspNetCore.Authentication.Cookies;
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

//services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
//    .AddCookie(opt =>
//    {
//        opt.SlidingExpiration = false;
//        // TODO: make this configurable
//        opt.ExpireTimeSpan = TimeSpan.FromHours(8);
//        opt.LoginPath = "/";
//    })
//    .AddCookieDistributedTicketStore()
//    .AddSaml2();
services.AddAuthorizationCore();

services.AddSaml2();

services.AddOptions<CertificateOptions>()
    .Bind(builder.Configuration.GetSection("Saml2"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

// Certificate management
services.AddSingleton<CertificateContainer>();
services.AddHostedService<CertificateManager>();

// Creates options e.g. for "/metadata". Creation and post configuration (PostConfigure) happens scoped on every request!
services.AddScoped(sp => sp.GetRequiredService<IOptionsSnapshot<Saml2Configuration>>().Value);
services.AddOptions<Saml2Configuration>()
    .Bind(builder.Configuration.GetSection("Saml2:IDP"))
    .PostConfigure<CertificateContainer>((saml2, certificateContainer) =>
    {
        saml2.AllowedAudienceUris.Add(saml2.Issuer);

        saml2.DecryptionCertificates.AddRange(certificateContainer.GetCertificates());
        saml2.SigningCertificate = certificateContainer.GetSignatureCertificate();
    });

// Metadata management
services.AddSingleton<MetadataContainer>();
services.AddHostedService<MetadataManager>();

services.AddOptions<RelyingPartyOptions>()
    .Bind(builder.Configuration.GetSection("Saml2"));       // Binds appsettings->Saml2->RelyingParties


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
app.MapSAMLEndpoints();

app.Run();
