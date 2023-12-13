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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.Assert.*;

public class CertificationAuthorityTest {

    private static final String ORG_NAME = "Bright Mammoth Brain GmbH";

    private static final String ROOT_NAME = "Root I";
    private static final String ROOT_ALIAS = "root-i";
    private static final int ROOT_VALIDITY = 40;

    private static final String ISSUER_NAME = "L1 CA I I";
    private static final String ISSUER_ALIAS = "l1-ca-i-i";
    private static final int ISSUER_VALIDITY = 40;

    private static final int KEY_SIZE = 2048;

    private static char[] SYSTEM_KEY_PASSWORD = "1234567890123456".toCharArray();
    private List<char[]> passwords = new ArrayList<>();

    private Path systemKeyPath;
    private Path rootKeyPasswordPath;
    private Path rootKeyStorePath;
    private Path issuerKeyPasswordPath;
    private Path issuerKeyStorePath;
    private Path rootCertificatePath;

    @Before
    public void init() throws IOException, CryptoException {
        systemKeyPath = Files.createTempFile("systemKey.", ".properties");
        rootKeyPasswordPath = Files.createTempFile("root.", ".properties");
        rootKeyStorePath = Files.createTempFile("root.", ".jks");
        issuerKeyPasswordPath = Files.createTempFile("issuer.", ".properties");
        issuerKeyStorePath = Files.createTempFile("issuer.", ".jks");
        rootCertificatePath = Files.createTempFile("root.", ".crt");

        generateSystemKey();
        generateRoot();
        generateIssuer();
    }

    @After
    public void finish() {
        for (char[] password: passwords) {
            //System.out.println("password: "+new String(password));
            for (char c: password) {
                assertEquals('*', c);
            }
        }
    }

    @Test
    public void testCertificationAuthority() throws IOException, CryptoException {
        CertificateAndKey request = PKI.generateSelfSignedCertificateRequest("My Device", KEY_SIZE);

        CertificationAuthority ca = CertificationAuthorityBuilder.create().
                setIssuerAlias(ISSUER_ALIAS).
                setSystemKeyResource(systemKeyPath.toString()).
                setSystemKeyPassword(getSystemKeyPassword()).
                setIssuerPasswordResource(issuerKeyPasswordPath.toString()).
                setIssuerKeyStoreResource(issuerKeyStorePath.toString()).
                setRootCertificateResource(rootCertificatePath.toString()).
                build();

        assertNotNull(ca);

        Date notValidAfter = DateUtil.addYears(new Date(), 1);
        X509Certificate deviceCertificate = ca.issueCertificate(request.getCertificate(),  notValidAfter);

        assertNotNull(deviceCertificate);
        assertTrue(PKI.verifyCertificateSignature(deviceCertificate, ca.getIssuerCertificate()));

        //System.out.println(deviceCertificate);
    }

    private char[] getSystemKeyPassword() {
        char[] copy = Arrays.copyOf(SYSTEM_KEY_PASSWORD, SYSTEM_KEY_PASSWORD.length);
        passwords.add(copy);
        return copy;
    }

    private void generateSystemKey() throws IOException, CryptoException {
        BufferedWriter writer = Files.newBufferedWriter(systemKeyPath);
        PKI.generateSystemKey(writer, getSystemKeyPassword());
        writer.close();
    }

    private void generateRoot() throws IOException, CryptoException {
        // Generate self signed root certificate
        CertificateAndKey root = PKI.generateRoot(ORG_NAME, ROOT_NAME, ROOT_VALIDITY, KEY_SIZE);

        // Generate password and store it encrypted with system key
        char[] password = generateAndStorePassword(rootKeyPasswordPath);
        //System.out.println("Password=" + new String(password));

        // Store root certificate and key in keytore, protected with password
        PKI.generateKeyStore(root, ROOT_ALIAS, password, Files.newOutputStream(rootKeyStorePath));
        PKI.storeCertificate(root.getCertificate(), Files.newOutputStream(rootCertificatePath));
    }

    private void generateIssuer() throws IOException, CryptoException {
        // Load root key and certificate
        CertificateAndKey root = loadKeyStore(rootKeyStorePath, rootKeyPasswordPath, ROOT_ALIAS);

        // Generate L1CA certificate and key
        CertificateAndKey l1ca = PKI.generateL1CA(ORG_NAME, ISSUER_NAME, ISSUER_VALIDITY, KEY_SIZE, root);

        // Generate password and store it encrypted with system key
        char[] password = generateAndStorePassword(issuerKeyPasswordPath);
        //System.out.println("Password=" + new String(password));

        // Store L1CA certificate and key in keytore, protected with password
        PKI.generateKeyStore(l1ca, ISSUER_ALIAS, password, Files.newOutputStream(issuerKeyStorePath));
    }


    private char[] generateAndStorePassword(Path path) throws IOException, CryptoException {
        BufferedReader systemKeyReader = Files.newBufferedReader(systemKeyPath);
        BufferedWriter passwordWriter = Files.newBufferedWriter(path);
        char[] password = PKI.generatePassword(systemKeyReader, getSystemKeyPassword(), passwordWriter);
        passwordWriter.close();
        systemKeyReader.close();
        return password;
    }

    private char[] loadPassword(Path path) throws IOException, CryptoException {
        BufferedReader systemKeyReader = Files.newBufferedReader(systemKeyPath);
        BufferedReader passwordReader = Files.newBufferedReader(path);
        char[] password = PKI.readPassword(systemKeyReader, getSystemKeyPassword(), passwordReader);
        passwordReader.close();
        systemKeyReader.close();
        return password;
    }

    private CertificateAndKey loadKeyStore(Path keyStorePath, Path passwordPath, String alias) throws IOException, CryptoException {
        // Read and decrypt password of keystore
        char[] password = loadPassword(passwordPath);

        // Load key and certificate
        InputStream is = Files.newInputStream(keyStorePath);
        CertificateAndKey certificateAndKey = PKI.loadKeyStore(alias, is, password);
        is.close();

        return certificateAndKey;
    }


}