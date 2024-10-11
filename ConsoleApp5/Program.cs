using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensibility;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

internal class Program
{
    private static async Task Main(string[] args)
    {
        // Get the Token acquirer factory instance. By default it reads an appsettings.json
        // file if it exists in the same folder as the app (make sure that the 
        // "Copy to Output Directory" property of the appsettings.json file is "Copy if newer").
        var tokenAcquirerFactory = TokenAcquirerFactory.GetDefaultInstance();

        // Add console logging or other services if you wish
        tokenAcquirerFactory.Services.AddLogging(
            (loggingBuilder) => loggingBuilder.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Warning)
                                              .AddConsole());

        var sp = tokenAcquirerFactory.Build();
        var ta = tokenAcquirerFactory.GetTokenAcquirer();

        X509Certificate2 certificate = GetCertificateFromConfig(sp);

        var thumbprint = Base64UrlEncoder.Encode(certificate.GetCertHash(HashAlgorithmName.SHA256));

        var reqCnf = $@"{{""kty"":""RSA"",""x5t#S256"":""{thumbprint}"",""kid"":""{thumbprint}""}}";

        var token = await ta.GetTokenForAppAsync(
            "https://vault.azure.net/.default",
            new AcquireTokenOptions() { 
                PopPublicKey = thumbprint,
                PopClaim = reqCnf });
    }

    /// <summary>
    /// This just uses Id.Web to get the cert from config. You can use any method to get the cert.
    /// </summary>
    private static X509Certificate2 GetCertificateFromConfig(IServiceProvider sp)
    {
        var appOptions = sp.GetRequiredService<IOptions<MicrosoftIdentityApplicationOptions>>();
        CertificateDescription credentialDescription = new CertificateDescription(appOptions.Value.ClientCredentials!.First());
        DefaultCertificateLoader.LoadFirstCertificate(new[] { credentialDescription });
        X509Certificate2 certificate = credentialDescription.Certificate!;
        return certificate;
    }

}
