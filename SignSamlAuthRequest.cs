using System;
using System.Deployment.Internal.CodeSigning;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Schema;
using Microsoft.IdentityModel.Tokens;
//using NullGuard.PostSharp;

namespace SAMLNM
{
    /// <summary>
    /// Signs the Saml Auth Request using the specified certificate
    /// </summary>
    //[NonNullAspect]
    public class SignSamlAuthRequest
    {
        private readonly X509Certificate2 _signingCertificate;
        private readonly string _messageXml;
        private XmlDocument _documentToSign;
        private readonly CultureInfo _cultureInfo = CultureInfo.InvariantCulture;
        private string _referenceUri;
        private readonly string _assertionId;
        static SignSamlAuthRequest()
        {
            RegisterRsaSha256SignatureAlgorithm();
        }
        
        public static void RegisterRsaSha256SignatureAlgorithm()
        {
            //CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), SecurityAlgorithms.RsaSha256Signature);
            HashAlgorithm hashAlg = HashAlgorithm.Create("SHA256");

        }
        public SignSamlAuthRequest(string messageXml, X509Certificate2 signingCertificate, string assertionId)
        {
            _signingCertificate = signingCertificate;
            _messageXml = messageXml;
            _assertionId = assertionId;
        }
        public string SignRequest()
        {
            _documentToSign = LoadMessageXml(_assertionId);
            var xmlDigitalSignature = ComputeDigitalSignature();
            return GetSignedXml();

        }
        private XmlDocument LoadMessageXml(string assertionId)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                ValidationType = ValidationType.Schema
            };
            settings.ValidationFlags = XmlSchemaValidationFlags.ProcessInlineSchema;
            var reader = XmlReader.Create(new StringReader(_messageXml), settings);
            var doc = new XmlDocument { PreserveWhitespace = false };
            doc.Load(reader);

            var xMan = new XmlNamespaceManager(doc.NameTable);
            xMan.AddNamespace(prefix: "ns3", uri: "urn:oasis:names:tc:SAML:2.0:protocol");
            var xNode = doc.SelectSingleNode("/ns3:AuthRequest/@IssueInstant", xMan);
            if (xNode != null)
            {
                xNode.Value = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffK");
                
            }
            xNode = doc.SelectSingleNode("/ns3:AuthnRequest/@ID", xMan);
            if(xNode != null)
            {
                xNode.Value = assertionId;
                _referenceUri = xNode.Value;
            }
            return doc;
        }

        private XmlElement ComputeDigitalSignature()
        {
            var signedXml = CreateSignedXml();
            signedXml.ComputeSignature();
            var signatureElement = signedXml.GetXml();
            _documentToSign.DocumentElement.AppendChild(_documentToSign.ImportNode(signatureElement, true));
            return signatureElement;
        }
        private CustomSignedXml CreateSignedXml()
        {
            var signedXml = new CustomSignedXml(_documentToSign)
            {
                SigningKey = _signingCertificate.GetRSAPrivateKey(),
                KeyInfo = CreateKeyInfo()
            };
            signedXml.SignedInfo.CanonicalizationMethod = SecurityAlgorithms.ExclusiveC14nWithComments;
            signedXml.SignedInfo.SignatureMethod = SecurityAlgorithms.RsaSha256Signature;
            signedXml.AddReference(CreateReference());
            return signedXml;
        }
        private Reference CreateReference()
        {
            var reference = new Reference
            {
                Uri = string.Concat('#', _referenceUri),
                DigestMethod = SecurityAlgorithms.Sha256Digest
            };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            return reference;
        }
        private KeyInfo CreateKeyInfo()
        {
            var keyInfoData = new KeyInfoX509Data(_signingCertificate);
            keyInfoData.AddSubjectName(_signingCertificate.Subject);
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(keyInfoData);
            return keyInfo;
        }
        private string GetSignedXml()
        {
            return _documentToSign.InnerXml;
        }
    }
    public class CustomSignedXml: SignedXml
    {
        public CustomSignedXml(XmlDocument doc): base(doc)
        {
            return;
        }
        public override XmlElement GetIdElement(XmlDocument document, string id)
        {
            var wsSecurityUtilityNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
            var ns = new XmlNamespaceManager(document.NameTable);
            ns.AddNamespace("wssu", wsSecurityUtilityNamespace);
            var element = document?.SelectSingleNode($"//*[wssu:Id=\"{id}\"]", ns) as XmlElement;
            element = element ?? base.GetIdElement(document, id);
            return base.GetIdElement(document, id);
        }
    }
}
