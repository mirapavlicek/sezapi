using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using System.Net.Http.Headers;
using System.IO;
using System.Text;

static string CreateJwtWithCert(string clientId, string audience, X509Certificate2 cert)
{
  var signingKey = new X509SecurityKey(cert);
  var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);
  var claims = new[]
  {
    new Claim(JwtRegisteredClaimNames.Iss, clientId),
    new Claim(JwtRegisteredClaimNames.Sub, clientId),
    new Claim(JwtRegisteredClaimNames.Aud, audience),
    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
  };

  var token = new JwtSecurityToken(
    claims: claims,
    notBefore: DateTime.UtcNow,
    expires: DateTime.UtcNow.AddHours(1),
    signingCredentials: signingCredentials
  );
  return new JwtSecurityTokenHandler().WriteToken(token);
}

static string ComputeSha256OfCertificateDer(X509Certificate2 cert)
{
  byte[] der = cert.RawData;
  using var sha256 = SHA256.Create();
  byte[] hash = sha256.ComputeHash(der);
  return Convert.ToHexString(hash).ToLowerInvariant();
}

static byte[] ReadPfxBytes(string inputPath)
{
  byte[] raw = File.ReadAllBytes(inputPath);
  if (raw.Length > 0 && raw[0] == 0x30)
    return raw;
  string text = Encoding.ASCII.GetString(raw);
  return Convert.FromBase64String(text.Trim());
}

try
{
  var configuration = new ConfigurationBuilder()
      .SetBasePath(AppContext.BaseDirectory)
      .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
      .Build();

  var clientId = configuration["Jwt:ClientId"] ?? "25488627_KrajskaZdravotniVerejnyTest";
  var audience = configuration["Jwt:Audience"] ?? "https://jsuint-auth-t2.csez.cz/connect/token";
  var certFileName = configuration["Certificate:Path"] ?? "client-cert.pfx";
  var certPassword = configuration["Certificate:Password"] ?? "hesloCertifikatu";
  var apiUrl = configuration["Api:Url"] ?? "https://gwy-ext-sec-t2.csez.cz/notifikace/api/v1/kanaly/katalog";

  var certPath = Path.Combine(AppContext.BaseDirectory, certFileName);

  //Načtení certifikátu EZCA I do DER formátu pokud není. Jinak EZCA II certifikát nepřevádíme a vrací se nezměněný obsah PFX souboru.
  byte[] pfxBytes = ReadPfxBytes(certPath);

  using var clientCert = new X509Certificate2(pfxBytes, certPassword, X509KeyStorageFlags.DefaultKeySet);

  //Metoda pro vypočtení SHA-256 hashe DER certifikátu pro vytváření ClientID pro staré EZCA I certifikáty.
  string certDerSha256 = ComputeSha256OfCertificateDer(clientCert);
  Console.WriteLine($"SHA-256 DER certifikátu: {certDerSha256}");

  string jwt = CreateJwtWithCert(clientId, audience, clientCert);

  var httpClientHandler = new HttpClientHandler { ClientCertificateOptions = ClientCertificateOption.Manual };
  httpClientHandler.ClientCertificates.Add(clientCert);

  using var http = new HttpClient(httpClientHandler);
  var request = new HttpRequestMessage(HttpMethod.Get, apiUrl);
  request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
  var response = await http.SendAsync(request);
  var content = await response.Content.ReadAsStringAsync();
  Console.WriteLine($"Status: {(int)response.StatusCode} {response.ReasonPhrase}");
  Console.WriteLine(content);
  Console.WriteLine();
  Console.WriteLine("Stiskněte Enter pro ukončení...");
  Console.ReadLine();
}
catch (Exception ex)
{
  Console.WriteLine("Došlo k chybě:");
  Console.WriteLine(ex.ToString());
  Console.WriteLine();
  Console.WriteLine("Stiskněte Enter pro ukončení...");
  Console.ReadLine();
}



