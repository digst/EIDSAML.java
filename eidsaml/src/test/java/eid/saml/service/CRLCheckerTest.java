package eid.saml.service;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import eid.saml.util.TestConstants;

public class CRLCheckerTest extends BaseServiceTest {

    @DisplayName("Test revocation check on valid certificate using OCSP")
    @Test
    public void testOcspCheckOnValidCertificate() throws Exception {
        EIDSAMLService.getConfig().setCRLCheckEnabled(false);
        EIDSAMLService.getConfig().setOcspCheckEnabled(true);

        byte[] validCert = Base64.getDecoder().decode(TestConstants.VALID_CERTIFICATE.getBytes(Charset.forName("UTF-8")));
        
        ByteArrayInputStream bis = new ByteArrayInputStream(validCert);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(bis);
        
        List<X509Certificate> x509Certificates = Collections.singletonList(certificate);
        Set<X509Certificate> validCertificates = CRLChecker.checkCertificates(x509Certificates, null);
        
        Assertions.assertEquals(1, validCertificates.size());
    }
    
    @DisplayName("Test revocation check on valid certificate using CRL")
    @Test
    public void testCrlCheckOnValidCertificate() throws Exception {
        EIDSAMLService.getConfig().setCRLCheckEnabled(true);
        EIDSAMLService.getConfig().setOcspCheckEnabled(false);
        
        byte[] validCert = Base64.getDecoder().decode(TestConstants.VALID_CERTIFICATE.getBytes(Charset.forName("UTF-8")));
        
        ByteArrayInputStream bis = new ByteArrayInputStream(validCert);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(bis);
        
        List<X509Certificate> x509Certificates = Collections.singletonList(certificate);
        Set<X509Certificate> validCertificates = CRLChecker.checkCertificates(x509Certificates, null);
        
        Assertions.assertEquals(1, validCertificates.size());
    }

    @DisplayName("Test revocation check on revoked certificate using OCSP")
    @Test
    public void testOcspCheckOnRevokedCertificate() throws Exception {
        EIDSAMLService.getConfig().setCRLCheckEnabled(false);
        EIDSAMLService.getConfig().setOcspCheckEnabled(true);

        byte[] validCert = Base64.getDecoder().decode(TestConstants.REVOKED_CERTIFICATE.getBytes(Charset.forName("UTF-8")));
        
        ByteArrayInputStream bis = new ByteArrayInputStream(validCert);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(bis);
        
        List<X509Certificate> x509Certificates = Collections.singletonList(certificate);
        Set<X509Certificate> validCertificates = CRLChecker.checkCertificates(x509Certificates, null);
        
        Assertions.assertNotNull(validCertificates);
        Assertions.assertEquals(0, validCertificates.size());
    }
    
    @DisplayName("Test revocation check on revoked certificate using CRL")
    @Test
    public void testCrlCheckOnRevokedCertificate() throws Exception {
        EIDSAMLService.getConfig().setCRLCheckEnabled(true);
        EIDSAMLService.getConfig().setOcspCheckEnabled(false);

        byte[] validCert = Base64.getDecoder().decode(TestConstants.REVOKED_CERTIFICATE.getBytes(Charset.forName("UTF-8")));
        
        ByteArrayInputStream bis = new ByteArrayInputStream(validCert);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(bis);
        
        List<X509Certificate> x509Certificates = Collections.singletonList(certificate);
        Set<X509Certificate> validCertificates = CRLChecker.checkCertificates(x509Certificates, null);
        
        Assertions.assertNotNull(validCertificates);
        Assertions.assertEquals(0, validCertificates.size());
    }
}
