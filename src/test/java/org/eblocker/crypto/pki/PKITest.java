/*
 * Copyright 2020 eBlocker Open Source UG (haftungsbeschraenkt)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the EUPL
 * (the "License"); You may not use this work except in compliance with
 * the License. You may obtain a copy of the License at:
 *
 *   https://joinup.ec.europa.eu/page/eupl-text-11-12
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package org.eblocker.crypto.pki;

import org.eblocker.crypto.CryptoException;
import org.eblocker.crypto.util.DateUtil;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CRLReason;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class PKITest {

    private static final Logger LOG = LoggerFactory.getLogger(PKITest.class);

    private final static int KEYSIZE = 2048;
    private final static String ORGNAME = "Bright Mammoth Brain GmbH";

    @Test
    public void testGenerateRoot() throws Exception {
        String name = "Root CA I";
        int validityYears = 50;

        Date t1 = new Date();
        CertificateAndKey root = PKI.generateRoot(ORGNAME, name, validityYears, KEYSIZE);
        Date t2 = new Date();

        assertNotNull(root);

        X509Certificate certificate = root.getCertificate();

        Date notBefore = certificate.getNotBefore();
        Date notAfter = certificate.getNotAfter();
        //System.out.println("t1 = "+format.format(t1));
        //System.out.println("t2 = "+format.format(t2));
        //System.out.println("nb = "+format.format(notBefore));
        //System.out.println("na = "+format.format(notAfter));
        assertFalse(DateUtil.stripMillis(t1, 0).after(notBefore));
        assertFalse(DateUtil.stripMillis(t2, 1).before(notBefore));
        assertEquals(DateUtil.addYears(notBefore, validityYears), notAfter);

        assertTrue(PKI.verifyCertificateSignature(root.getCertificate(), root.getCertificate()));
    }

    @Test
    public void testGenerateL1CA() throws Exception {
        CertificateAndKey root = PKI.generateRoot(ORGNAME, "Root CA I", 50, KEYSIZE);
        String name = "L1 CA I I";
        int validityYears = 40;

        Date t1 = new Date();
        CertificateAndKey l1ca = PKI.generateL1CA(ORGNAME, name, validityYears, KEYSIZE, root);
        Date t2 = new Date();

        assertNotNull(l1ca);

        X509Certificate certificate = l1ca.getCertificate();

        Date notBefore = certificate.getNotBefore();
        Date notAfter = certificate.getNotAfter();
        assertFalse(DateUtil.stripMillis(t1, 0).after(notBefore));
        assertFalse(DateUtil.stripMillis(t2, 1).before(notBefore));
        assertEquals(DateUtil.addYears(notBefore, validityYears), notAfter);

        assertTrue(PKI.verifyCertificateSignature(l1ca.getCertificate(), root.getCertificate()));

        assertFalse(PKI.verifyCertificateSignature(l1ca.getCertificate(), l1ca.getCertificate()));
        assertFalse(PKI.verifyCertificateSignature(root.getCertificate(), l1ca.getCertificate()));

        byte[] rootKeyHash = PKI.getPublicKeyHash(root.getCertificate());
        byte[] l1caKeyHash = PKI.getPublicKeyHash(l1ca.getCertificate());
        byte[] rootKeyHash2 = PKI.getPublicKeyHash(root.getCertificate());
        byte[] l1caKeyHash2 = PKI.getPublicKeyHash(l1ca.getCertificate());
        assertFalse(Arrays.equals(rootKeyHash, l1caKeyHash));
        assertFalse(Arrays.equals(rootKeyHash, l1caKeyHash2));
        assertTrue(Arrays.equals(rootKeyHash, rootKeyHash2));
        assertTrue(Arrays.equals(l1caKeyHash, l1caKeyHash2));
    }

    @Test
    public void testSelfSignedCertificateRequest() throws CryptoException, IOException, CertificateParsingException {
        CertificateAndKey certificateAndKey = PKI.generateSelfSignedCertificateRequest("unit-test", 1024, Arrays.asList("xkcd.org", "108.168.185.170"));

        Assert.assertEquals("CN=unit-test", certificateAndKey.getCertificate().getSubjectDN().getName());
        Set<List<?>> names = new HashSet<>(certificateAndKey.getCertificate().getSubjectAlternativeNames());
        Assert.assertEquals(3, names.size());
        Assert.assertTrue(names.contains(Arrays.asList(2, "xkcd.org")));
        Assert.assertTrue(names.contains(Arrays.asList(2, "108.168.185.170")));
        Assert.assertTrue(names.contains(Arrays.asList(7, "108.168.185.170")));
    }

    @Test
    public void testGenerateSelfSignedDeviceCertificate() throws Exception {
        String name = "Device 1";

        Date t1 = new Date();
        CertificateAndKey deviceCertificate = PKI.generateSelfSignedCertificateRequest(name, KEYSIZE);
        Date t2 = new Date();

        assertNotNull(deviceCertificate);

        X509Certificate certificate = deviceCertificate.getCertificate();

        Date notBefore = certificate.getNotBefore();
        Date notAfter = certificate.getNotAfter();
        //System.out.println("t1 = "+format.format(t1));
        //System.out.println("t2 = "+format.format(t2));
        //System.out.println("nb = "+format.format(notBefore));
        //System.out.println("na = "+format.format(notAfter));
        assertFalse(DateUtil.stripMillis(t1, 0).after(notBefore));
        assertFalse(DateUtil.stripMillis(t2, 1).before(notBefore));
        assertEquals(DateUtil.addYears(notBefore, 1), notAfter);
    }

    @Test
    public void testGenerateDeviceCertificate() throws Exception {
        CertificateAndKey root = PKI.generateRoot(ORGNAME, "Root CA I", 50, KEYSIZE);
        CertificateAndKey l1ca = PKI.generateL1CA(ORGNAME, "L1 CA I I", 40, KEYSIZE, root);
        String name = "Device 1";
        int validityYears = 1;
        CertificateAndKey deviceRequest = PKI.generateSelfSignedCertificateRequest(name, KEYSIZE);
        Date notValidAfter = DateUtil.addYears(new Date(), validityYears);

        Date t1 = new Date();
        X509Certificate deviceCertificate = PKI.generateSignedCertificate(deviceRequest.getCertificate(), ORGNAME, name, notValidAfter, l1ca);
        Date t2 = new Date();

        assertNotNull(deviceCertificate);

        Date notBefore = deviceCertificate.getNotBefore();
        Date notAfter = deviceCertificate.getNotAfter();
        assertFalse(DateUtil.stripMillis(t1, 0).after(notBefore));
        assertFalse(DateUtil.stripMillis(t2, 1).before(notBefore));
        assertEquals(DateUtil.addYears(notBefore, validityYears), notAfter);
    }

    @Test
    public void testGenerateCrl() throws Exception {
        CertificateAndKey root = PKI.generateRoot(ORGNAME, "Root CA I", 50, KEYSIZE);
        CertificateAndKey l1ca = PKI.generateL1CA(ORGNAME, "L1 CA I I", 40, KEYSIZE, root);

        BigInteger s1 = BigInteger.valueOf(1000L);
        BigInteger s2 = BigInteger.valueOf(10002000L);
        BigInteger s3 = BigInteger.valueOf(100020003000L);

        BigInteger s4 = BigInteger.valueOf(100020003001L);

        Date d1 = DateUtil.stripMillis(new Date(), 0);
        Date d2 = new Date(d1.getTime()-1000L*360*24*30);
        Date d3 = new Date(d1.getTime()-1000L*360*24*30);

        Date nextUpdate = new Date(d1.getTime()+1000L*360*24*30);

        RevocationReason r1 = RevocationReason.DEACTIVATED;
        RevocationReason r2 = RevocationReason.REPLACED;
        RevocationReason r3 = RevocationReason.REVOKED;

        RevocationInfo[] revocationInfos = new RevocationInfo[]{
                new RevocationInfo(s1, d1, r1),
                new RevocationInfo(s2, d2, r2),
                new RevocationInfo(s3, d3, r3)
        };
        X509CRL crl = PKI.generateCrl(Arrays.asList(revocationInfos), l1ca, nextUpdate);

        assertEquals(nextUpdate, crl.getNextUpdate());

        assertEquals(s1, crl.getRevokedCertificate(s1).getSerialNumber());
        assertEquals(d1, crl.getRevokedCertificate(s1).getRevocationDate());
        assertEquals(CRLReason.CESSATION_OF_OPERATION, crl.getRevokedCertificate(s1).getRevocationReason());

        assertEquals(s2, crl.getRevokedCertificate(s2).getSerialNumber());
        assertEquals(d2, crl.getRevokedCertificate(s2).getRevocationDate());
        assertEquals(CRLReason.SUPERSEDED, crl.getRevokedCertificate(s2).getRevocationReason());

        assertNull(crl.getRevokedCertificate(s4));
    }

    @Test
    public void testGenerateLoadAndStoreTrustStore() throws Exception {
        char[] password = "PASSWORD".toCharArray();
        CertificateAndKey root1 = PKI.generateRoot(ORGNAME, "Root CA I", 50, KEYSIZE);
        CertificateAndKey root2 = PKI.generateRoot(ORGNAME, "Root CA II", 50, KEYSIZE);
        CertificateAndKey root3 = PKI.generateRoot(ORGNAME, "Root CA III", 50, KEYSIZE);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PKI.generateTrustStore(
                new X509Certificate[]{root1.getCertificate(), root2.getCertificate(), root3.getCertificate()},
                new String[]{"Root CA I", "Root CA II", "Root CA III"},
                password, baos);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        X509Certificate[] certificates = PKI.loadTrustStore(bais, password);

        baos = new ByteArrayOutputStream();
        PKI.storeCertificates(certificates, baos);

        String pem = new String(baos.toByteArray());
        String[] certs = pem.split("-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----");

        assertEquals(3, certs.length);
        certs[0] = certs[0] + "-----END CERTIFICATE-----";
        certs[1] = "-----BEGIN CERTIFICATE-----" + certs[1] + "-----END CERTIFICATE-----";
        certs[2] = "-----BEGIN CERTIFICATE-----" + certs[2];

        int i = 0;
        for (String cert: certs) {
            certificates[i++] = PKI.loadCertificate(new ByteArrayInputStream(cert.getBytes()));
        }
        assertTrue(certificates[0].getSubjectX500Principal().getName().contains("Root CA"));
        assertTrue(certificates[1].getSubjectX500Principal().getName().contains("Root CA"));
        assertTrue(certificates[2].getSubjectX500Principal().getName().contains("Root CA"));

        LOG.info("cert-0 {}", certificates[0].getSubjectX500Principal().getName());
        LOG.info("cert-1 {}", certificates[1].getSubjectX500Principal().getName());
        LOG.info("cert-2 {}", certificates[2].getSubjectX500Principal().getName());
    }

    @Test
    public void testGenerateTrustStore() throws Exception {
        CertificateAndKey[] roots = {
                PKI.generateRoot(ORGNAME, "Root CA I", 50, KEYSIZE),
                PKI.generateRoot(ORGNAME, "Root CA II", 50, KEYSIZE),
                PKI.generateRoot(ORGNAME, "Root CA III", 50, KEYSIZE),
                PKI.generateRoot(ORGNAME, "Root CA III", 50, KEYSIZE) // intentional duplicate dn
        };

        X509Certificate[] certificates = new X509Certificate[roots.length];
        for(int i = 0; i < roots.length; ++i) {
            certificates[i] = roots[i].getCertificate();
        }

        KeyStore store = PKI.generateTrustStore(certificates);

        Assert.assertEquals(certificates[0], store.getCertificate("cert_0:o=" + ORGNAME.toLowerCase() + ",cn=root ca i"));
        Assert.assertEquals(certificates[1], store.getCertificate("cert_1:o=" + ORGNAME.toLowerCase() + ",cn=root ca ii"));
        Assert.assertEquals(certificates[2], store.getCertificate("cert_2:o=" + ORGNAME.toLowerCase() + ",cn=root CA iii"));
        Assert.assertEquals(certificates[3], store.getCertificate("cert_3:o=" + ORGNAME.toLowerCase() + ",cn=root CA iii"));
    }

    @Test
    public void testGeneratePassword() throws Exception {

    }

    @Test
    public void testReadPassword() throws Exception {

    }

    @Test
    public void testGenerateKeyStore() throws Exception {

    }

    @Test
    public void testLoadKeyStore() throws Exception {

    }

    @Test
    public void testLoadCertificates() throws Exception {
        String path = ClassLoader.getSystemResource("sample-certs/certificates.pem").toURI().getPath();
        FileInputStream in = new FileInputStream(path);

        X509Certificate[] certificates = PKI.loadCertificates(in);

        Assert.assertNotNull(certificates);
        Assert.assertEquals(4, certificates.length);
        Assert.assertEquals("CN=Microsoft IT SSL SHA2, OU=Microsoft IT, O=Microsoft Corporation, L=Redmond, ST=Washington, C=US", certificates[0].getSubjectDN().getName());
        Assert.assertEquals("CN=Symantec Class 3 EV SSL CA - G3, OU=Symantec Trust Network, O=Symantec Corporation, C=US", certificates[1].getSubjectDN().getName());
        Assert.assertEquals("CN=test-sspev.verisign.com, OU=Infrastructure Operations Symantec SSPEV Revoked, O=Symantec Corporation, STREET=350 Ellis Street, L=Mountain View, ST=California, OID.2.5.4.17=94043, C=US, SERIALNUMBER=2158113, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US", certificates[2].getSubjectDN().getName());
        Assert.assertEquals("CN=www.microsoft.com, O=Microsoft Corporation, L=Redmond, ST=WA, C=US", certificates[3].getSubjectDN().getName());
    }

    @Test
    public void testLoadPrivateKey() throws Exception {
        PrivateKey key = PKI.loadPrivateKey(ClassLoader.getSystemResourceAsStream("private.key"));

        Assert.assertEquals("RSA", key.getAlgorithm());
        Assert.assertEquals("PKCS#8", key.getFormat());
        Assert.assertEquals("8DF4E4DF1D3BEAD11AEA951E241A17D0EFC5D408C5C944B9BB072CD1ACEBC9DD", DatatypeConverter.printHexBinary(MessageDigest.getInstance("SHA-256").digest(key.getEncoded())));
    }

    @Test
    public void testStoreCertificate() throws Exception {

    }

    @Test
    public void testStoreRequest() throws Exception {

    }

    @Test
    public void testGetCN() throws Exception {
        CertificateAndKey root1 = PKI.generateRoot(ORGNAME, "Root CA I", 50, KEYSIZE);

        String cn = PKI.getCN(root1.getCertificate());
        assertEquals("Root CA I", cn);
    }

    @Test
    public void testGetAuthorityKeyIdentifier() throws Exception {
        X509Certificate certificate = loadCertificate("sample-certs/MicrosoftITSSLSHA2");
        AuthorityKeyIdentifier aki = PKI.getAuthorityKeyIdentifier(certificate);
        Assert.assertNotNull(aki);
        Assert.assertNull(aki.getAuthorityCertIssuer());
        Assert.assertNull(aki.getAuthorityCertSerialNumber());
        Assert.assertArrayEquals(DatatypeConverter.parseHexBinary("e59d5930824758ccacfa085436867b3ab5044df0"), aki.getKeyIdentifier());

        certificate = loadCertificate("sample-certs/Verisign_Class_1_Public_Primary_CA.pem");
        aki = PKI.getAuthorityKeyIdentifier(certificate);
        Assert.assertNotNull(aki);
        Assert.assertEquals(new X500Principal("CN=VeriSign Class 1 Public Primary Certification Authority - G3, OU=\"(c) 1999 VeriSign, Inc. - For authorized use only\", OU=VeriSign Trust Network, O=\"VeriSign, Inc.\", C=US"),  new X500Principal(aki.getAuthorityCertIssuer().getNames()[0].getName().toASN1Primitive().getEncoded()));
        Assert.assertEquals(new BigInteger("8b5b75568454850b00cfaf3848ceb1a4", 16), aki.getAuthorityCertSerialNumber());
        Assert.assertNull(aki.getKeyIdentifier());
    }

    @Test
    public void testGetSubjectKeyIdentifier() throws Exception {
        X509Certificate certificate = loadCertificate("sample-certs/MicrosoftITSSLSHA2");
        Assert.assertArrayEquals(DatatypeConverter.parseHexBinary("51af24269cf468225780262b3b4662157b1ecca5"), PKI.getSubjectKeyIdentifier(certificate));


    }

    private X509Certificate loadCertificate(String resource) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        try (InputStream in = ClassLoader.getSystemResourceAsStream(resource)) {
            return (X509Certificate) certificateFactory.generateCertificate(in);
        }
    }

}