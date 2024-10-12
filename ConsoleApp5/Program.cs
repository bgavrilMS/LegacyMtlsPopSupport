using Azure.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensibility;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.S2S.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

internal class Program
{
    const string Authority = "https://login.microsoftonline.com/f645ad92-e38d-4d1a-b510-d1b09a74a8ca";
    const string ClientId = "88f91eac-c606-4c67-a0e2-a5e8a186854f";

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
        
        CertificateDescription credential = CertificateDescription.FromStoreWithDistinguishedName("CN=LabAuth.MSIDLab.com");
        DefaultCertificateLoader.LoadFirstCertificate([credential]);
        X509Certificate2 certificate = credential.Certificate!;

        ITokenAcquirer tokenAcquirer = tokenAcquirerFactory.GetTokenAcquirer(new MicrosoftIdentityApplicationOptions()
        {
            Authority = Authority, 
            ClientId = ClientId,
            ClientCredentials = [credential], 
            SendX5C = true
        });

        var thumbprint = Base64UrlEncoder.Encode(certificate.GetCertHash(HashAlgorithmName.SHA256));

        var reqCnf = $@"{{""kty"":""RSA"",""x5t#S256"":""{thumbprint}"",""kid"":""{thumbprint}""}}";

        AcquireTokenResult token = await tokenAcquirer.GetTokenForAppAsync(
            "https://vault.azure.net/.default",
            new AcquireTokenOptions() { 
                PopPublicKey = thumbprint,
                PopClaim = reqCnf });
    }

   

}
