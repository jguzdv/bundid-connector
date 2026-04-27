using Sustainsys.Saml2;
using Sustainsys.Saml2.Saml2P;
using Sustainsys.Saml2.WebSso;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;

namespace JGUZDV.BundId.SAMLProxy.SAML2;

internal static class BundIDHelpers
{
    public static List<X509Certificate2> LoadCertificate(IConfiguration configuration, string configPath = "SAML2:BundId")
    {
        var certPath = configuration[$"{configPath}:CertificatesPath"]
            ?? throw new ArgumentNullException($"{configPath}:CertificatesPath");

        var certPassword = configuration[$"{configPath}:CertificatePassword"];

        var result = new List<X509Certificate2>();

        foreach (var certFile in Directory.GetFiles(certPath, "*.pfx"))
        {
            try
            {
                var cert = X509CertificateLoader.LoadPkcs12FromFile(certFile, certPassword);
                if (cert.HasPrivateKey && cert.NotAfter > DateTimeOffset.UtcNow)
                {
                    result.Add(cert);
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to load certificate from {certFile}.", ex);
            }
        }

        return result;
    }

    public static void OnAuthenticationRequestCreated(Saml2AuthenticationRequest request, IdentityProvider provider, IDictionary<string, string> dictionary)
    {
        request.ExtensionContents.Add(XElement.Parse($"""
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
                <akdb:RequestedAttribute Name="{BundIdAttributes.BPK2}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.Gender}" RequiredAttribute="false" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.PersonalTitle}" RequiredAttribute="false" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.GivenName}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.Surname}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.Birthdate}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.BirthName}" RequiredAttribute="false" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.PlaceOfBirth}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.PostalCode}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.LocalityName}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.PostalAddress}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.Country}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.Nationality}" RequiredAttribute="false" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.Mail}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.EIDCitizenQaaLevel}" RequiredAttribute="false" />
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

    public static void OnAcsCommandResultCreated(CommandResult result, Saml2Response response)
    {
        result.Principal.Identities.First().AddClaim(new("issuer", response.Issuer.Id));
    }
}
