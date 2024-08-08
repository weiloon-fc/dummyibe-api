using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using System.Security.Cryptography.X509Certificates;
using Jose;
using Newtonsoft.Json;
using System.Collections;
using Microsoft.AspNetCore.ResponseCompression;
using System.Text;
using DummyIBE_API.Models;
using Org.BouncyCastle.Asn1.Ocsp;
using Newtonsoft.Json.Linq;

namespace DummyIBE_API.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class CertificateController : Controller
    {

        private readonly string _DirectoryPath;

        private readonly string _IBECertificateFileName = "ibe.crt";
        private readonly string _IBEPublicFileName = "ibe.pub";
        private readonly string _IBEPrivateFileName = "ibe.key";


        // Path of IBE Cert and Public Key (unencryptoed)
        // Can be generated using Certificate/GenerateRandomCertificate API
        private readonly string _IBECertificatePath;
        private readonly string _IBEPublicKeyPath;
        private readonly string _IBEPrivateKeyPath;

        // Path of Seat Select Public Key Certificate
        // Please manual download from seat admin site, and place into App_Data folder
        private readonly string _SeatSelectCertificate;

        public CertificateController()
        {
            _DirectoryPath = Path.Combine(AppContext.BaseDirectory, "App_Data");
            _IBECertificatePath = Path.Combine(_DirectoryPath, _IBECertificateFileName);
            _IBEPublicKeyPath = Path.Combine(_DirectoryPath, _IBEPublicFileName);
            _IBEPrivateKeyPath = Path.Combine(_DirectoryPath, _IBEPrivateFileName);
            _SeatSelectCertificate = Path.Combine(_DirectoryPath, "ACME_PublicKeyCertificate.crt");
        }

        [HttpGet]
        public IActionResult GenerateRandomCertificate()
        {
            // Generate public-private key pairs
            var keyGenerationParams = new KeyGenerationParameters(new SecureRandom(), 2048);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParams);
            var keyPairs = keyPairGenerator.GenerateKeyPair();

            // Generate Certificate
            var random = new SecureRandom();
            var certificateGenerator = new Org.BouncyCastle.X509.X509V3CertificateGenerator();
            var subjectDN = new X509Name("CN=Acme Co");
            var issuerDN = subjectDN;
            var serialNumber = Org.BouncyCastle.Math.BigInteger.ProbablePrime(120, new Random());

            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
            certificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(10));
            certificateGenerator.SetSubjectDN(subjectDN);
            certificateGenerator.SetPublicKey(keyPairs.Public);

            var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", keyPairs.Private, random);
            var cert = certificateGenerator.Generate(signatureFactory);

            string public_key = ConvertToPEM(keyPairs.Public);
            string private_key = ConvertToPEM(keyPairs.Private);
            string fileCert = ConvertToPEM(cert);

            GenerateKeyFile(public_key, _IBEPublicFileName);
            GenerateKeyFile(private_key, _IBEPrivateFileName);
            GenerateKeyFile(fileCert, _IBECertificateFileName);

            var resp = new
            {
                public_key,
                private_key,
                cert = fileCert
            };

            return Ok(resp);
        }

        [HttpPost]
        public IActionResult GetSingleSignOnToken([FromBody]SingleSignOnPayload payload)
        {
            if(!System.IO.File.Exists(_IBECertificatePath) || !System.IO.File.Exists(_IBEPublicKeyPath) || !System.IO.File.Exists(_IBEPrivateKeyPath))
            {
                GenerateRandomCertificate();
            }

            string seatSelectCert = System.IO.File.ReadAllText(_SeatSelectCertificate);
            string ibeCert = System.IO.File.ReadAllText(_IBECertificatePath);
            string ibePrivateKey = System.IO.File.ReadAllText(_IBEPrivateKeyPath);

            RSA? rsaCert = GetPublicKey(seatSelectCert);
            if (rsaCert == null)
                return Content("Failed to get token");

            X509Certificate2 rsaPrivateCert = X509Certificate2.CreateFromPem(ibeCert, ibePrivateKey);

            string jweRequest = Jose.JWT.Encode(payload, rsaCert, Jose.JweAlgorithm.RSA_OAEP, Jose.JweEncryption.A256GCM, null, null, new Jose.JwtSettings { JsonMapper = new NewtonsoftMapper() });
            string token = Jose.JWT.Encode(jweRequest, rsaPrivateCert.GetRSAPrivateKey(), Jose.JwsAlgorithm.PS256);

            return Content(token ?? "Failed to get token");
        }

        [HttpPost]
        public async Task<IActionResult> SelectedSeat()
        {
            string token;
            using StreamReader reader = new StreamReader(Request.Body, Encoding.UTF8);
            token = await reader.ReadToEndAsync();
            token = token.Replace("token=", "");

            string seatSelectCert = System.IO.File.ReadAllText(_SeatSelectCertificate);
            string ibeCert = System.IO.File.ReadAllText(_IBECertificatePath);
            string ibePrivateKey = System.IO.File.ReadAllText(_IBEPrivateKeyPath);

            RSA? rsaCert = GetPublicKey(seatSelectCert);
            if (rsaCert == null)
                return Content("Failed to get payload");

            X509Certificate2 rsaPrivateCert = X509Certificate2.CreateFromPem(ibeCert, ibePrivateKey);
            string jweResponse = Jose.JWT.Decode(token, rsaCert, Jose.JwsAlgorithm.PS256);
            string strResponse = Jose.JWT.Decode(jweResponse, rsaPrivateCert.GetRSAPrivateKey(), Jose.JweAlgorithm.RSA_OAEP, Jose.JweEncryption.A256GCM);

            var payload = JsonConvert.DeserializeObject<SelectedSeatPayload>(strResponse);

            return View("SelectedSeat", payload);
        }

        public record class NewtonsoftMapper : IJsonMapper
        {
            public T? Parse<T>(string json) => JsonConvert.DeserializeObject<T>(json);

            public string Serialize(object obj) => JsonConvert.SerializeObject(obj);
        }

        private void GenerateKeyFile(string fileContent, string fileName)
        {
            if(!Directory.Exists(_DirectoryPath))
                Directory.CreateDirectory(_DirectoryPath);

            string certFilePath = Path.Combine(_DirectoryPath, fileName);

            if (System.IO.File.Exists(certFilePath))
                System.IO.File.Delete(certFilePath);

            System.IO.File.WriteAllText(certFilePath, fileContent);
        }

        private string ConvertToPEM(object obj)
        {
            using var sw = new StringWriter();
            var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
            pemWriter.WriteObject(obj);
            pemWriter.Writer.Flush();
            string pem = sw.ToString();

            return pem;
        }

        private RSA? GetPublicKey(string certificate)
        {
            if (!string.IsNullOrWhiteSpace(certificate))
            {
                if (certificate.StartsWith("-----BEGIN RSA PUBLIC KEY-----"))
                {
                    RSA rsa = RSA.Create();
                    rsa.ImportFromPem(certificate);
                    return rsa;
                }
                else if (certificate.StartsWith("-----BEGIN CERTIFICATE-----"))
                {
                    return X509Certificate2.CreateFromPem(certificate).GetRSAPublicKey();
                }
            }

            return null;
        }
    }
}
