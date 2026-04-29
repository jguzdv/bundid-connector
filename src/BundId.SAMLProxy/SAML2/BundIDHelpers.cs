using System.Security.Cryptography.X509Certificates;

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
}
