using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Build.Utilities;
using System;
using System.IO;
using System.IO.Compression;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Permissions;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace SAMLNM.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHostingEnvironment _hostingEnvironment;

        public HomeController(IHostingEnvironment hostingEnvironment)
        {
            _hostingEnvironment = hostingEnvironment;
        }
        //public readonly ICertificateProvider _certificateProvider;
        public IActionResult Index()
        {
            return View();
        }
        private static byte[] StringToByteArray(string st)
        {
            try
            {
                byte[] bytes = new byte[st.Length];
                for (int i = 0; i < st.Length; i++)
                {
                    bytes[i] = (byte)st[i];
                }
                return bytes;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        private static X509Certificate2 LoadCertificate(string fileName, string password)
        {
            //if (httpRequest.Url.ToString().Contains("localhost:"))
                return new X509Certificate2(fileName, password);
            //else
              //  return new X509Certificate2(fileName, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        }
        public ActionResult SendSamlLoginRequest()
        {
            var issueinstant  = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture);

            var assertionId = string.Concat('_', Convert.ToString(Guid.NewGuid()));
            var issuerUrl = "https://localhost:44390/Consumer/Index";
            //var idpUrl = "https://dev-v05dsv7ifxszhoo4.us.auth0.com/samlp/CUMd3Vp4txSyQRMVxU6biafRJ8D0IjkI";
            var idpUrl = "https://auth.pingone.com/50bec962-8ef5-404d-a629-60e039010a1e/saml20/idp/sso";
            var issuer = "https://localhost:44390/";
            string req = GetRequest(assertionId, issuerUrl, idpUrl, issueinstant, issuer);
            ////My code ends
            string htmlFilePath = Path.Combine(_hostingEnvironment.WebRootPath, "new-sp.pfx");
            var signSAMLAuthRequest = new SignSamlAuthRequest(req, LoadCertificate(htmlFilePath, "12345"), assertionId);
            var authRequest = signSAMLAuthRequest.SignRequest();
            //create sso session
            //loggers
            var samlDataBytes = Encoding.UTF8.GetBytes(authRequest);
            var base64AuthRequestString = Convert.ToBase64String(samlDataBytes);
            ViewBag.uri = idpUrl;
            ViewBag.SamlRequest = base64AuthRequestString;
            return View("SamlLogin");
        }

        public string GetRequest(string assertionId,string issuerUrl,string idpUrl, string issueInstant, string issuer)
        {
            try
            {
                using (MemoryStream output = new MemoryStream())
                {
                    Encoding utf8noBOM = new UTF8Encoding(false);
                    XmlWriterSettings xws = new XmlWriterSettings();
                    xws.Indent = true;
                    xws.OmitXmlDeclaration = true;
                    xws.Encoding = utf8noBOM;

                    using (XmlWriter xw = XmlWriter.Create(output, xws))
                    {
                        xw.WriteStartElement("saml2p", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                        xw.WriteAttributeString("ID", assertionId);
                        xw.WriteAttributeString("Version", "2.0");
                        xw.WriteAttributeString("ForceAuthn", "false");
                        xw.WriteAttributeString("IssueInstant", issueInstant);
                        xw.WriteAttributeString("Destination", idpUrl);
                        xw.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
                        xw.WriteAttributeString("AssertionConsumerServiceURL",issuerUrl );

                        xw.WriteStartElement("saml2", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                        xw.WriteString(issuer);
                        xw.WriteEndElement();

                        xw.WriteEndElement();
                    }

                        string stringRequest = System.Text.Encoding.UTF8.GetString(output.ToArray());
                        var xmlRequest = new XmlDocument();
                        xmlRequest.LoadXml(stringRequest);
                    /*
                        string base64;
                        using (MemoryStream xmlStream = new MemoryStream())
                        {
                            using (var zip = new DeflateStream(xmlStream, CompressionMode.Compress))
                            {
                                zip.Write(output.ToArray(), 0, output.ToArray().Length);
                            }

                            base64 = Convert.ToBase64String(xmlStream.ToArray());
                        }
                        return base64;
                    */
                    return stringRequest;
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// //From ChatGPT
        /// </summary>
        /// <param name="idpUrl"></param>
        /// <param name="issuerUrl"></param>
        /// <returns></returns>
        public string CreateAuthRequest()
        {
            // Create a unique ID for the request
            var assertionId = string.Concat('_', Convert.ToString(Guid.NewGuid()));
            var issuerUrl = "https://localhost:44390/Consumer/Index";
            //var idpUrl = "https://dev-v05dsv7ifxszhoo4.us.auth0.com/samlp/CUMd3Vp4txSyQRMVxU6biafRJ8D0IjkI";
            var idpUrl = "https://auth.pingone.com/50bec962-8ef5-404d-a629-60e039010a1e/saml20/idp/sso";
            // Create the AuthnRequest XML document
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + assertionId + "\" Version=\"2.0\" IssueInstant=\"" + DateTime.Now.ToUniversalTime().ToString("o") + "\" Destination=\"" + idpUrl + "\" AssertionConsumerServiceURL=\"" + issuerUrl + "\">" +
                "<saml:Issuer>" + issuerUrl + "</saml:Issuer>" +
                "<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"/>" +
                "<samlp:RequestedAuthnContext Comparison=\"exact\">"+
                "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>"+
                "</samlp:RequestedAuthnContext>" +   
                "<samlp:Scoping>"+        
                "<samlp:IDPList>"+
                "<samlp:IDPEntry ProviderID=\"https://auth.pingone.com\"/>"+        
                "</samlp:IDPList>"+
                "</samlp:Scoping>"+
                "<saml:Conditions NotBefore=\"2023-02-22T15:16:17.123Z\" NotOnOrAfter=\"2024-02-22T16:16:17.123Z\">"+
                "<saml:AudienceRestriction>"+
                "<saml:Audience>https://localhost:44390</saml:Audience>" +
                "</saml:AudienceRestriction>"+
                "</saml:Conditions>" +
                "</samlp:AuthnRequest>");

            // Sign the AuthnRequest using the private key of the issuer
            //RSA rsa = RSA.Create();
            //rsa.FromXmlString("MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQCng9C4q8CdAtrQ\r\ngTnaysD1Ez2D4L1knbsc0jZ8G4pcXHHwsUEpbu7zJwgvrWny5GtMwby4NkYf/9Qc\r\nydqHTPQOE/kVAnBZ9ESQkiXgLYVjaifQQ++/mYsWCTLt7g4E3APLWNflSoy6pn41\r\n9gQkrorWbZh/m1xDrWpa6H87kFD0i+2QV4bcZeiz2uck8g42h4KRjxH1RiYnM8CR\r\n6gf+59n8GQSNjJruJhQF2W0Qh7wZLV4zlaggM/8OlcOxUX3SFiP2IX0E9yparNRx\r\nMcKOqLaC8kGdDF3F+FdRZm/SPN5yXQgBjzNYRBACbA1J8dMYH6mq4l8RQDgrNs61\r\nPrGOa3XrAgMBAAECggEBAKNDo6/5JZdh6uYArOSDbCDwCap45d4kpPNoJlY7eVSf\r\nfSV7fOjnB9jQl/fv6i0jVzjOMiLQMvSJILCWQ3hPFiaKbN9/KwVhP1owNt4RP8ou\r\n8nLXY9m3yolFme+vbtZpoQEVrAX77MEV+DibeFpQC10GH/Vu9DO51siXhToGZACS\r\ns851J2lG10z/0RTLy3R7Yabi1uE2slG0rvnG7EVU4owlbXKn8bY8U0iUVUz+xqdX\r\nX+PdhFtl5+UU17gXSGVnGMdfQC7w07WPZSCSZ6JWyY97BXbUiSSVLOySz8IsJ1cq\r\nt+roITLhcEQcxM9cRKrkHVf37odEKyGl9VrvCNs6slECgYEA3s1wC27yy4TemymM\r\nGQZcZLobKnMKuCO+yrW2vG+I5DLt2S6F+dh2yYfsB8B/oH5t9ZLfMROeTGPkjErf\r\neD6OAYo06kxCJa/8qlDYbtER5u7Tzqq4dIEEWnKDA6zxD7da3sTe6G87mKIr0lxg\r\nVUpb/boveGBOvR2UVVsyKD9Mnp0CgYEAwHl96jIl3RT8YnjLLAn+ca+EIyFAO6ou\r\nXNhWUN+cvwitgfUTY44KofsD31sHbYqUakYpLZCYeWXn56W99A0Rrz2uUwkNoU00\r\nJEJKJPcsO8Is36YxosYqi4+CV4yYiVtMvlssJuxjnf9wrpAqA/3GlqRX6XnS8F96\r\nvFwwB/UUvCcCgYEAkRjJNyjyBYhqUDImgsWZth9dQa/Z80GUJv9gGieoxrREIYQi\r\nzCskcOqL1CCQ/TxY7+zOXW+hT65eUN8R2YUjhe0zuMIg8dpCechcqw6M0hAG8DhO\r\nF9FNvHmGyQX/l3SZQSqE4GpQLX6vezedpO3gKsTt1T8jCBYTW+MgLwXKKCECgYEA\r\npiR5Lz6IdpVV4r54SpR54bJq8lQSeS5GhPhtUbQkPraD50kgqnAC952Q0y1ldQYJ\r\nZM8ZXm6RX0E69Deah178o/MvVhfbfyAAYUgjblM6CH9tcsSn1eUO9pczINWJGhAI\r\nZ8yViSfGOa00nEpvKjDWSlSkWjJBhiI09QDyqPvCIUMCgYEAnqwU0JGYMiQQtyVD\r\nHE98zABnOtOecm8GltGWAQHc9j6xYO3AuGdmw8gWwGoMNkhXNTiCHIIvtGw5dHQF\r\nuPlH3b9wcevAK+QEwqXRmeqe9XS4uDvV3cLwXpkcifW/7jDdVaYlV53dgZWV9mvP\r\nEJoRmqS4wNI+lR+dzI5r8Yb7V0A=");
            string htmlFilePath = Path.Combine(_hostingEnvironment.WebRootPath, "new-sp.pfx");
            var cert = LoadCertificate(htmlFilePath, "12345");
            SignedXml signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = cert.PrivateKey;

            Reference reference = new Reference("");
            reference.Uri = "#" + assertionId;
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);
            signedXml.ComputeSignature();
            XmlElement signature = signedXml.GetXml();
            xmlDoc.DocumentElement.AppendChild(signature);

            // Convert the AuthnRequest to a string
            string authRequest = xmlDoc.OuterXml;

            return authRequest;
        }


    }
}
