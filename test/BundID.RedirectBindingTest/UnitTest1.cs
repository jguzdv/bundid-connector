using Microsoft.AspNetCore.Http;
using Sustainsys.Saml2.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace BundID.RedirectBindingTest
{
    public class UnitTest1
    {
        [Fact]
        public async Task Test1()
        {
            var now = TimeProvider.System.GetUtcNow();
            var certificate = X509CertificateLoader.LoadPkcs12FromFile("D:\\Temp\\SAML2\\bund-id\\bundid.uni-mainz.de.pfx", "TODO");

            var v3Binding = new Sustainsys.Saml2.Bindings.HttpRedirectBinding();

            var authnRequest = new Sustainsys.Saml2.Samlp.AuthnRequest() {
                Issuer = "https://sp.example.com/issuer",
                IssueInstant = now.UtcDateTime,
                AssertionConsumerServiceUrl = "http://sp.example.com/acs",
                Id = "message_ID",
            };

            var xml = new SamlXmlWriter().Write(authnRequest);

            var v3Message = new Sustainsys.Saml2.Bindings.OutboundSaml2Message
            {
                Xml = xml.DocumentElement!,
                Destination = "https://example.com/sso",
                Binding = Sustainsys.Saml2.Constants.BindingUris.HttpRedirect,
                SigningCertificate = certificate,
                RelayState = "relayStateValue",
                Name = Sustainsys.Saml2.Constants.SamlRequest
            };

            var httpResponse = new DefaultHttpContext().Response;
            await v3Binding.BindAsync(httpResponse, v3Message);

            var location = httpResponse.Headers.Location[0];
            var queryString = new Uri(location).Query;

            var parameters = queryString.Trim('?').Split('&');
            var parameterDict = parameters.ToDictionary(p => p.Split('=')[0], p => p.Split('=')[1]);

            var signedRequest = $"SAMLRequest={parameterDict["SAMLRequest"]}&RelayState={parameterDict["RelayState"]}&SigAlg={parameterDict["SigAlg"]}";
            var signature = parameterDict["Signature"];

            var isValid = certificate.GetRSAPublicKey()!.VerifyData(
                System.Text.Encoding.UTF8.GetBytes(signedRequest),
                Convert.FromBase64String(Uri.UnescapeDataString(signature)),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            Assert.True(isValid);
        }
    }
}
