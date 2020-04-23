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
import org.eblocker.crypto.CryptoService;
import org.eblocker.crypto.CryptoServiceFactory;
import org.eblocker.crypto.keys.KeyHandler;
import org.eblocker.crypto.openssl.OpenSslRsaKeyPairGeneratorProvider;
import org.eblocker.crypto.util.DateUtil;
import org.eblocker.crypto.util.EncodingUtil;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CRLReason;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class PKI {
    private static final Logger log = LoggerFactory.getLogger(PKI.class);

    private static final String KEYGEN_PROVIDER_NAME = "openSslRsa";
    private static final String SIGNER_PROVIDER_NAME = "BC";
    private static final String CERTIF_PROVIDER_NAME = "BC";

    private static final String KEY_ALGORITHM = "RSA";
    private static final String CERT_SIGN_ALOGORITHM = "SHA256withRSA";

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new OpenSslRsaKeyPairGeneratorProvider());
    }

    private PKI() {
    }

    public static CertificateAndKey generateRoot(String orgName, String rootName, int validityYears, int keySize) throws CryptoException {
        Date notBefore = getStartDate();
        Date notAfter = getEndDate(notBefore, validityYears);
        return generateRoot(orgName, rootName, notBefore, notAfter, keySize);
    }

    public static CertificateAndKey generateRoot(String orgName, String rootName, Date notBefore, Date notAfter, int keySize) throws CryptoException {
        KeyPair keyPair = generateRSAKeyPair(keySize);
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded()));
        X500Name dn = getSubjectDN(orgName, rootName);

        X509v3CertificateBuilder builder;
        try {
            builder = new X509v3CertificateBuilder(
                dn,
                generateSerialNumber(),
                notBefore,
                notAfter,
                dn,
                subjectPublicKeyInfo
            )
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(1))
                .addExtension(Extension.authorityKeyIdentifier, false, new BcX509ExtensionUtils().createAuthorityKeyIdentifier(subjectPublicKeyInfo))
                .addExtension(Extension.subjectKeyIdentifier, false, new BcX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo))
                .addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
            ;

        } catch (CertIOException e) {
            String msg = "Cannot generate certificate builder for root: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }

        return new CertificateAndKey(generateCertificate(builder, keyPair.getPrivate()), keyPair.getPrivate());
    }

    public static CertificateAndKey generateL1CA(String orgName, String name, int validityYears, int keySize, CertificateAndKey root) throws CryptoException {
        KeyPair keyPair = generateRSAKeyPair(keySize);
        SubjectPublicKeyInfo authorityPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(root.getCertificate().getPublicKey().getEncoded()));
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded()));
        Date startDate = getStartDate();

        X509v3CertificateBuilder builder;
        try {
            builder = new JcaX509v3CertificateBuilder(
                root.getCertificate(),
                generateSerialNumber(),
                startDate,
                getEndDate(startDate, validityYears),
                getSubjectDN(orgName, name),
                keyPair.getPublic()
            )
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
                .addExtension(Extension.authorityKeyIdentifier, false, new BcX509ExtensionUtils().createAuthorityKeyIdentifier(authorityPublicKeyInfo))
                .addExtension(Extension.subjectKeyIdentifier, false, new BcX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo))
                .addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
            ;

        } catch (CertIOException e) {
            String msg = "Cannot generate certificate builder: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }

        return new CertificateAndKey(generateCertificate(builder, root.getKey()), keyPair.getPrivate());
    }

    public static CertificateAndKey generateSelfSignedCertificateRequest(String name, int keySize) throws CryptoException, IOException {
        return generateSelfSignedCertificateRequest(name, keySize, Collections.emptyList());
    }

    public static CertificateAndKey generateSelfSignedCertificateRequest(String name, int keySize, List<String> subjectAlternativeNames) throws CryptoException, IOException {
        KeyPair keyPair = generateRSAKeyPair(keySize);
        return generateSelfSignedCertificateRequest(name, keyPair, subjectAlternativeNames);
    }

     public static CertificateAndKey generateSelfSignedCertificateRequest(String name, KeyPair keyPair, List<String> subjectAlternativeNames) throws CryptoException, IOException {
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded()));
        Date startDate = getStartDate();
        X500Name dn = getSubjectDN(null, name);

        X509v3CertificateBuilder builder;
        try {
            builder = new X509v3CertificateBuilder(
                dn,
                generateSerialNumber(),
                startDate,
                getEndDate(startDate, 1),
                dn,
                subjectPublicKeyInfo
            )
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                .addExtension(Extension.authorityKeyIdentifier, false, new BcX509ExtensionUtils().createAuthorityKeyIdentifier(subjectPublicKeyInfo))
                .addExtension(Extension.subjectKeyIdentifier, false, new BcX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo))
                .addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature))
            ;

            GeneralNamesBuilder generalNames = new GeneralNamesBuilder();
            for(String altName : subjectAlternativeNames) {
                generalNames.addName(new GeneralName(GeneralName.dNSName, altName));
                if (altName.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                    generalNames.addName(new GeneralName(GeneralName.iPAddress, altName));
                }
            }
            builder.addExtension(Extension.subjectAlternativeName, false, generalNames.build());
        } catch (CertIOException e) {
            String msg = "Cannot generate certificate builder for self signed device certificate: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }

        return new CertificateAndKey(generateCertificate(builder, keyPair.getPrivate()), keyPair.getPrivate());
    }

    public static X509Certificate generateTLSServerCertificate(X509Certificate request, String orgName, String name, Date notValidAfter, CertificateAndKey l1ca) throws CryptoException {
        return doGenerateSignedCertificate(request, orgName, name, notValidAfter, l1ca, KeyPurposeId.id_kp_serverAuth);
    }

    public static X509Certificate generateTLSClientCertificate(X509Certificate request, String orgName, String name, Date notValidAfter, CertificateAndKey l1ca) throws CryptoException {
        return doGenerateSignedCertificate(request, orgName, name, notValidAfter, l1ca, KeyPurposeId.id_kp_clientAuth);
    }

    public static X509Certificate generateSignedCertificate(X509Certificate request, String orgName, String name, Date notValidAfter, CertificateAndKey l1ca) throws CryptoException {
        return doGenerateSignedCertificate(request, orgName, name, notValidAfter, l1ca);
    }

    private static X509Certificate doGenerateSignedCertificate(X509Certificate request, String orgName, String name, Date notValidAfter, CertificateAndKey l1ca, KeyPurposeId...keyPurposeIds) throws CryptoException {
        PublicKey publicKey = request.getPublicKey();
        SubjectPublicKeyInfo authorityPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(l1ca.getCertificate().getPublicKey().getEncoded()));
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(publicKey.getEncoded()));
        Date startDate = getStartDate();
        if (notValidAfter.after(l1ca.getCertificate().getNotAfter())) {
            notValidAfter = l1ca.getCertificate().getNotAfter();
        }

        X509v3CertificateBuilder builder;
        try {
            builder = new JcaX509v3CertificateBuilder(
                    l1ca.getCertificate(),
                    generateSerialNumber(),
                    startDate,
                    notValidAfter,
                    new JcaX509CertificateHolder(request).getSubject(),
                    publicKey
            )
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.authorityKeyIdentifier, false, new BcX509ExtensionUtils().createAuthorityKeyIdentifier(authorityPublicKeyInfo))
                    .addExtension(Extension.subjectKeyIdentifier, false, new BcX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo))
                    .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment))
                    ;
            if (keyPurposeIds != null && keyPurposeIds.length > 0) {
                builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(keyPurposeIds));
            }
            if (keyPurposeIds != null && Arrays.asList(keyPurposeIds).contains(KeyPurposeId.id_kp_serverAuth)) {
                if (request.getSubjectAlternativeNames() == null || request.getSubjectAlternativeNames().isEmpty()) {
                    builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.dNSName, getCN(request))));
                } else {
                    builder.addExtension(Extension.subjectAlternativeName, false, createGeneralNames(request));
                }
            }

        } catch (CertIOException e) {
            String msg = "Cannot generate certificate builder: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        } catch (CertificateEncodingException | CertificateParsingException e) {
            log.error("malformed request", e);
            throw new CryptoException("malformed request", e);
        }

        return generateCertificate(builder, l1ca.getKey());
    }

    private static GeneralNames createGeneralNames(X509Certificate request) throws CertificateParsingException {
        GeneralNamesBuilder builder = new GeneralNamesBuilder();
        for(List<?> alternativeName : request.getSubjectAlternativeNames()) {
            builder.addName(new GeneralName((Integer)alternativeName.get(0), (String) alternativeName.get(1)));
        }
        return builder.build();
    }

    public static X509CRL generateCrl(List<RevocationInfo> revocationInfos, CertificateAndKey l1ca, Date nextUpdate) throws CryptoException {

        SubjectPublicKeyInfo authorityPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(l1ca.getCertificate().getPublicKey().getEncoded()));

        X509v2CRLBuilder crlBuilder;
        try {
            crlBuilder = new JcaX509v2CRLBuilder(
                    l1ca.getCertificate(),
                    new Date()
            );
            crlBuilder.setNextUpdate(nextUpdate);
            crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, new BcX509ExtensionUtils().createAuthorityKeyIdentifier(authorityPublicKeyInfo));

            crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf((new Date()).getTime())));

            for (RevocationInfo revocationInfo : revocationInfos) {
                crlBuilder.addCRLEntry(revocationInfo.getSerialNumber(), revocationInfo.getRevocationDate(), revocationInfo.getRevocationReason().getReasonCode());
            }

        } catch (CertIOException e) {
            String msg = "Cannot generate CRL builder: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }

        return generateCrl(crlBuilder, l1ca.getKey());
    }

    public static boolean verifyCertificateSignature(X509Certificate certificate, X509Certificate assumedSigner) throws CryptoException {
        try {
            X509CertificateHolder signed = new X509CertificateHolder(certificate.getEncoded());
            X509CertificateHolder signer = new X509CertificateHolder(assumedSigner.getEncoded());
            ContentVerifierProvider verifierProvider = new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(signer);
            return signed.isSignatureValid(verifierProvider);

        } catch (IOException|CertificateEncodingException|OperatorCreationException|CertException e) {
            String msg = "Cannot verify certificate signature: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }
    }

    public static byte[] getPublicKeyHash(X509Certificate certificate) {
        byte[] bytes = certificate.getPublicKey().getEncoded();
        Digest sha1 = new SHA1Digest();
        sha1.update(bytes, 0, bytes.length);
        byte[] digest = new byte[sha1.getDigestSize()];
        sha1.doFinal(digest, 0);
        return digest;
    }

    public static void generateSystemKey(BufferedWriter writer, char[] password) throws IOException, CryptoException {
        byte[] systemKey = KeyHandler.createKey();
        CryptoService cryptoService = CryptoServiceFactory.getInstance().setPassword(password).build();
        KeyHandler.storeKey(systemKey, writer, cryptoService);
    }

    private static CryptoService getSystemKeyCryptoService(BufferedReader reader, char[] password) throws IOException, CryptoException {
        // CryptoService using password to decrypt system key
        CryptoService cryptoService = CryptoServiceFactory.getInstance().setPassword(password).build();
        // CryptoService using system key
        return CryptoServiceFactory.getInstance().setKey(KeyHandler.loadKey(reader, cryptoService)).build();
    }

    public static char[] generatePassword(BufferedReader systemKeyReader, char[] systemKeyPassword, BufferedWriter writer) throws IOException, CryptoException {
        CryptoService cryptoService = getSystemKeyCryptoService(systemKeyReader, systemKeyPassword);
        byte[] key = KeyHandler.createKey();
        char[] password = Hex.encodeHex(key);
        char[] copy = Arrays.copyOf(password, password.length);
        KeyHandler.storeKey(EncodingUtil.toBytes(password), writer, cryptoService);
        return copy;
    }

    public static char[] readPassword(BufferedReader systemKeyReader, char[] systemKeyPassword, BufferedReader reader) throws IOException, CryptoException {
        CryptoService cryptoService = getSystemKeyCryptoService(systemKeyReader, systemKeyPassword);
        byte[] encodedPassword = KeyHandler.loadKey(reader, cryptoService);
        return EncodingUtil.toChars(encodedPassword);
    }

    public static void generateKeyStore(CertificateAndKey certificateAndKey, String alias, char[] password, OutputStream out) throws IOException, CryptoException {
        generateKeyStore(certificateAndKey.getKey(), alias, password, out, "JKS", certificateAndKey.getCertificate());
    }

    public static void generateKeyStore(CertificateAndKey certificateAndKey, String alias, char[] password, OutputStream out, String keyStoreType, X509Certificate...chain) throws IOException, CryptoException {
        X509Certificate[] completeChain = new X509Certificate[chain.length+1];
        completeChain[0] = certificateAndKey.getCertificate();
        for (int i = 0; i < chain.length; i++) {
            completeChain[i+1] = chain[i];
        }
        generateKeyStore(certificateAndKey.getKey(), alias, password, out, keyStoreType, completeChain);
    }

    private static void generateKeyStore(PrivateKey key, String alias, char[] password, OutputStream out, String keyStoreType, X509Certificate...certificates) throws IOException, CryptoException {
        if (certificates == null) {
            certificates = new X509Certificate[]{};
        }
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null, null);
            keyStore.setKeyEntry(alias, key, password, certificates);
            keyStore.store(out, password);

        } catch (GeneralSecurityException e) {
            String msg = "Cannot generate key store: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }

    }

    public static void generateTrustStore(X509Certificate[] certificates, String[] aliases, char[] password, OutputStream out) throws IOException, CryptoException {
        if (certificates == null || aliases == null || certificates.length != aliases.length) {
            String msg = "Cannot generate trust store with invalid data: " +
                    (certificates == null ? "(null)" : certificates.length) +
                    "/" +
                    (aliases == null ? "(null)" : aliases.length);
            log.error(msg);
            throw new CryptoException(msg);
        }
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);
            for (int i = 0; i < certificates.length; i++) {
                keyStore.setCertificateEntry(aliases[i], certificates[i]);
            }
            keyStore.store(out, password);

        } catch (GeneralSecurityException e) {
            String msg = "Cannot generate key store: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }
    }

    public static KeyStore generateTrustStore(X509Certificate[] certificates) throws IOException, CryptoException {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);

            int count = 0;
            for (X509Certificate certificate : certificates) {
                keyStore.setCertificateEntry("cert_" + count + ":" + certificate.getSubjectDN().toString(), certificate);
                ++count;
            }

            return keyStore;
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            throw new CryptoException("Failed to generate key store", e);
        }
    }

    public static CertificateAndKey loadKeyStore(String alias, InputStream in, char[] password) throws IOException, CryptoException {
        try {
            KeyStore keyStore = loadKeyStore(in, password);
            PrivateKey key = (PrivateKey) keyStore.getKey(alias, password);
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            return new CertificateAndKey(certificate, key);

        } catch (GeneralSecurityException e) {
            String msg = "Cannot load key store: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }
    }

    public static KeyStore loadKeyStore(InputStream in, char[] password) throws IOException, CryptoException {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(in, password);
            return keyStore;

        } catch (GeneralSecurityException e) {
            String msg = "Cannot load key store: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }
    }

    public static X509Certificate[] loadTrustStore(InputStream in, char[] password) throws IOException, CryptoException {
        try {
            List<X509Certificate> certificates = new ArrayList<>();
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(in, password);
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
                if (certificate != null) {
                    certificates.add(certificate);
                }
            }
            return certificates.toArray(new X509Certificate[certificates.size()]);

        } catch (GeneralSecurityException e) {
            String msg = "Cannot load key store: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }
    }

    public static X509Certificate loadCertificate(InputStream in) throws IOException, CryptoException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(in);

        } catch (GeneralSecurityException e) {
            String msg = "Cannot load certificate: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        } finally {
            in.close();
        }
    }

    public static X509Certificate[] loadCertificates(InputStream in) throws IOException, CryptoException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
            try (PEMParser parser = new PEMParser(reader)) {

                List<X509Certificate> certificates = new ArrayList<>();
                JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

                Object object;
                while ((object = parser.readObject()) != null) {
                    try {
                        certificates.add(converter.getCertificate((X509CertificateHolder) object));
                    } catch (CertificateException e) {
                        throw new CryptoException("Failed to load certificate", e);
                    }
                }
                return certificates.toArray(new X509Certificate[certificates.size()]);
            }
        }
    }

    public static PrivateKey loadPrivateKey(InputStream in) throws IOException, CryptoException {
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(in))) {
            Object o = pemParser.readObject();
            if (o instanceof PrivateKeyInfo) {
                return new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) o);
            } else {
                String msg = "unexpected pem content: " + o.getClass();
                log.error(msg);
                throw new CryptoException(msg);
            }
        }
    }

    public static X509CRL loadCrl(InputStream in) throws IOException, CryptoException {
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(in))) {
            Object object = pemParser.readObject();
            if (object instanceof  X509CRLHolder) {
                try {
                    return new JcaX509CRLConverter().setProvider(CERTIF_PROVIDER_NAME).getCRL((X509CRLHolder)object);
                } catch (CRLException e) {
                    String msg = "could not convert parsed CRL";
                    log.error(msg, e);
                    throw new CryptoException(msg, e);
                }
            } else {
                String msg = "unexpected pem content: " + object.getClass();
                log.error(msg);
                throw new CryptoException(msg);
            }
        }
    }

    public static void storeCertificate(X509Certificate certificate, OutputStream os) throws IOException, CryptoException {
        try {
            writeToPEM("CERTIFICATE", certificate.getEncoded(), os);

        } catch (GeneralSecurityException e) {
            String msg = "Cannot store certificate: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }
    }

    public static void storeCertificates(X509Certificate[] certificates, OutputStream os) throws IOException, CryptoException {
        try {
            for (X509Certificate certificate: certificates) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                writeToPEM("CERTIFICATE", certificate.getEncoded(), baos);
                os.write(baos.toByteArray());
            }

        } catch (GeneralSecurityException e) {
            String msg = "Cannot store certificates: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }
    }

    public static void storePrivateKey(PrivateKey privateKey, OutputStream os) throws IOException, CryptoException {
        writeToPEM("PRIVATE KEY", privateKey.getEncoded(), os);
    }

    public static void storeCrl(X509CRL crl, OutputStream os) throws IOException, CryptoException {
        try {
            writeToPEM("X509 CRL", crl.getEncoded(), os);

        } catch (GeneralSecurityException e) {
            String msg = "Cannot store CRL: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }
    }

    private static void writeToPEM(String title, byte[] encoded, OutputStream os) throws IOException {
        PemObject pem = new PemObject(title, encoded);
        try (PemWriter writer = new PemWriter(new OutputStreamWriter(os))) {
            writer.writeObject(pem);
            writer.close();
        }
    }

    private static X500Name getSubjectDN(String orgName, String name) {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);

        //x500NameBuilder.addRDN(BCStyle.C, "DE");
        if (orgName != null) x500NameBuilder.addRDN(BCStyle.O, orgName);
        //x500NameBuilder.addRDN(BCStyle.L, "Hamburg");
        //x500NameBuilder.addRDN(BCStyle.ST, "Hamburg");
        //x500NameBuilder.addRDN(BCStyle.EmailAddress, "info@eblocker.com");
        x500NameBuilder.addRDN(BCStyle.CN, name);

        return x500NameBuilder.build();
    }

    private static BigInteger generateSerialNumber() {
        UUID uuid = UUID.randomUUID();
        ByteBuffer bb = ByteBuffer.wrap(new byte[20]);
        bb.putInt(0); // Make sure that we get a positive number
        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());
        BigInteger i = new BigInteger(bb.array());
        return i;
    }

    private static Date getStartDate() {
        return new Date();
    }

    private static Date getEndDate(Date startDate, int validityYears) {
        Date endDate = DateUtil.addYears(startDate, validityYears);
        return endDate;
    }

    public static KeyPair generateRSAKeyPair(int keySize) throws CryptoException {
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance(KEY_ALGORITHM, KEYGEN_PROVIDER_NAME);
            kpGen.initialize(keySize, new SecureRandom());
            return kpGen.generateKeyPair();

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            String msg = "Cannot generate key pair: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }
    }

    private static X509Certificate generateCertificate(X509v3CertificateBuilder builder, PrivateKey key) throws CryptoException {
        try {
            ContentSigner signer = new JcaContentSignerBuilder(CERT_SIGN_ALOGORITHM).setProvider(SIGNER_PROVIDER_NAME).build(key);
            X509CertificateHolder certHolder = builder.build(signer);
            return new JcaX509CertificateConverter().setProvider(CERTIF_PROVIDER_NAME).getCertificate(certHolder);

        } catch (OperatorCreationException | CertificateException e) {
            String msg = "Cannot generate or sign certificate: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }
    }

    private static X509CRL generateCrl(X509v2CRLBuilder builder, PrivateKey key) throws CryptoException {
        try {
            ContentSigner signer = new JcaContentSignerBuilder(CERT_SIGN_ALOGORITHM).setProvider(SIGNER_PROVIDER_NAME).build(key);
            X509CRLHolder crlHolder = builder.build(signer);
            return new JcaX509CRLConverter().setProvider(CERTIF_PROVIDER_NAME).getCRL(crlHolder);

        } catch (OperatorCreationException | CRLException e) {
            String msg = "Cannot generate or sign CRL: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }
    }

    public static String getCN(X509Certificate certificate) throws CryptoException {
        X500Name x500name;
        try {
            x500name = new JcaX509CertificateHolder(certificate).getSubject();
        } catch (CertificateEncodingException e) {
            String msg = "Cannot decode certificate for find DN: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        return IETFUtils.valueToString(cn.getFirst().getValue());
    }

    public static AuthorityKeyIdentifier getAuthorityKeyIdentifier(X509Certificate certificate) {
        String oid = Extension.authorityKeyIdentifier.getId();
        byte[] extensionValue = certificate.getExtensionValue(oid);
        if (extensionValue == null) {
            return null;
        }
        ASN1OctetString akiOctetString = ASN1OctetString.getInstance(extensionValue);
        return AuthorityKeyIdentifier.getInstance(akiOctetString.getOctets());
    }

    public static byte[] getSubjectKeyIdentifier(X509Certificate certificate) {
        String oid = Extension.subjectKeyIdentifier.getId();
        byte[] extensionValue = certificate.getExtensionValue(oid);
        if (extensionValue == null) {
            return null;
        }
        ASN1OctetString akiOctetString = ASN1OctetString.getInstance(extensionValue);
        return SubjectKeyIdentifier.getInstance(akiOctetString.getOctets()).getKeyIdentifier();
    }

    public static Set<RevocationInfo> getRevocationInfoEntries(X509CRL crl) {
        Set<? extends X509CRLEntry> entries = crl.getRevokedCertificates();
        if (entries == null) {
            return Collections.emptySet();
        }
        return entries.stream()
                .map(PKI::getRevocationInfo)
                .collect(Collectors.toSet());
    }

    private static RevocationInfo getRevocationInfo(X509CRLEntry x509CRLEntry) {
        BigInteger serial = x509CRLEntry.getSerialNumber();
        Date date = x509CRLEntry.getRevocationDate();
        RevocationReason reason = getRevocationReason(x509CRLEntry.getRevocationReason());
        return new RevocationInfo(serial, date, reason);
    }

    private static RevocationReason getRevocationReason(CRLReason reason) {
        if (reason == null) {
            return null;
        }
        switch (reason) {
            case CESSATION_OF_OPERATION: return RevocationReason.DEACTIVATED;
            case PRIVILEGE_WITHDRAWN:    return RevocationReason.REVOKED;
            case SUPERSEDED:             return RevocationReason.REPLACED;
            default:                     return null;
        }
    }
}
