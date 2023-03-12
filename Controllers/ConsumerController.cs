using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Schema;

namespace SAMLNM.Controllers
{
    public class ConsumerController : Controller
    {
        public IActionResult Index(string SAMLResponse)
        {
            var data = Convert.FromBase64String(SAMLResponse);
            var base64Decoded = Encoding.UTF8.GetString(data);
            TempData["signedXml"] = base64Decoded;
            return RedirectToAction("SamlLogin", "Consumer");
        }
        public async Task<ActionResult> SamlLogin()
        {
            var signedXml = TempData["signedXml"].ToString();
            ClaimsPrincipal result = null;
            IsValidResponseXml(signedXml);

            if (!ValidateSamlResponseAssertion(signedXml))
            {
                return RedirectToAction("NotAuthorized", "Error");
            }
            try
            {
                ;//result = _authService.Authenticate(signedXml).ConfigureAwait(false);

            }
            catch (Exception ex)
            {
                //Login Failure
            }
            if (result != null && result.Identity.IsAuthenticated)
            {
                //Create Session
                return RedirectToAction("Index", "Home");
            }
            return RedirectToAction("GeneralError", "Home");
        }
        private void IsValidResponseXml(string SamlResponse)
        {
            var isValidResponseXml = true;//XmlUtil.IsXml(samlResponse);
        }
        private Assertion GetAssertion(string samlResponse)
        {
            var newAssertion = new Assertion();
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                ValidationType = ValidationType.Schema
            };
            settings.ValidationFlags = XmlSchemaValidationFlags.ProcessInlineSchema;
            var reader = XmlReader.Create(new StringReader(samlResponse), settings);
            var xmlDocument = new XmlDocument
            {
                PreserveWhitespace = true
            };
            xmlDocument.Load(reader);

            var xMan = new XmlNamespaceManager(xmlDocument.NameTable);
            xMan.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:protocol");
            xMan.AddNamespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
            xMan.AddNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");
            xMan.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            xMan.AddNamespace("Sw", "urn:swift:saml:Sw.01");

            var xStatusCode = xmlDocument.SelectSingleNode("/saml2p:Response/saml2p:Status/saml2p:StatusCode/@Value", xMan);
            var xSubjectDn = xmlDocument.SelectSingleNode("/Sw:SubjectDN", xMan);
            var xNotOnOrAfter = xmlDocument.SelectSingleNode("/saml2p:Response/saml2:Assertion/saml:Conditions/@NotOnOrAfter", xMan);
            var xInResponseTo = xmlDocument.SelectSingleNode("/saml2p:Response/@InResponseTo", xMan);

            if(xInResponseTo!= null && xNotOnOrAfter != null && xSubjectDn != null && xStatusCode != null)
            {
                newAssertion.AssertionId = xInResponseTo.Value;
                newAssertion.NotOnOrAfter = xNotOnOrAfter.Value;
                newAssertion.DistinguishedName = xSubjectDn.InnerText;
                newAssertion.ResponseStatus = xStatusCode.Value;
            }
            else
            {
                //Assertion is null or empty
            }
            return newAssertion;

        }
        private bool ValidateSamlResponseAssertion(string signedXml)
        {
            var isValidAssertion = false;
            var responseAssertion = GetAssertion(signedXml);
            var isValiddassertionId = VaidateAssertionId(responseAssertion.AssertionId);
            var isValidnotOnOrAfter = ValidateSamlResponseStatus(responseAssertion.NotOnOrAfter);
            var isValidStatusCode = ValidateSamlResponseStatus(responseAssertion.ResponseStatus);
            var isValidDistinguishedName = ValidateDistinguishedName(responseAssertion.DistinguishedName);

            // if all are true _authService.RemoveSSoAssertion(responseAssertion.AssertionId);
            isValidAssertion = true;
            return isValidAssertion;
        }
        private bool ValidateDistinguishedName(string assertionId)
        {
            ///check valid user from DB
            ///
            return true;
        }
        private bool ValidateSamlResponseStatus(string statusCode)
        {
            if(statusCode == "")//correct status code
            return true;
            else
                return false;

        }
        private bool VaidateAssertionId(string assertionId)
        {
            //checked from authservicde and return

            return true;
        }
        private bool ValidateAssertionExpires(string notOnOrAfter)
        {
            if (notOnOrAfter == null) return false;
            var currentTime = DateTime.UtcNow;//TimeProvider.Current.UtcNow;
            var expiresTime = Convert.ToDateTime(notOnOrAfter).ToUniversalTime();
            if(expiresTime < currentTime) return false;
            return true;
        }
        private class Assertion
        {
            public string AssertionId { get; set;}
            public string NotOnOrAfter { get; set;}
            public string ResponseStatus { get; set;}
            public string DistinguishedName { get; set;}

        }

    }
}
