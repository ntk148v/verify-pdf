const forge = require('node-forge');
const utf8 = require('utf8');

const {
  extractSignature,
  getMessageFromSignature,
  preparePDF,
} = require('./helpers');

// Decode utf-8 characters
const decodeAttributeValue = (attrs) => attrs.map((aggs)=> {
  aggs.value = utf8.decode(aggs.value);
  return aggs;
});

const extractSingleCertificateDetails = (cert) => {
  return {
    serialNumber: cert.serialNumber,
    issuedBy: decodeAttributeValue(cert.issuer.attributes),
    issuedTo: decodeAttributeValue(cert.subject.attributes),
    validityPeriod: cert.validity,
    pemCertificate: forge.pki.certificateToPem(cert),
  };
};

const extractCertificatesDetails = (certs) => certs
  .map(extractSingleCertificateDetails)
  .map((cert, i) => {
    if (i) return cert;
    return {
      clientCertificate: true,
      ...cert,
    };
  });

const getCertificatesInfoFromPDF = (pdf) => {
  const pdfBuffer = preparePDF(pdf);
  const { signatureStr } = extractSignature(pdfBuffer);

  return signatureStr.map(signature => {
    const { certificates } = getMessageFromSignature(signature);
    return extractCertificatesDetails(certificates);
  });
};

module.exports = {
  extractCertificatesDetails,
  getCertificatesInfoFromPDF,
};
