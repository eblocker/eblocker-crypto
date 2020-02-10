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
import org.eblocker.crypto.util.CertificateResourceLoader;
import org.eblocker.crypto.util.ResourceLoader;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class CertificationAuthorityBuilder {

    public static CertificationAuthorityBuilder create() {
        return new CertificationAuthorityBuilder();
    }

    private String orgName;

    private char[] systemKeyPassword;

    private String systemKeyResource;
    private String issuerPasswordResource;
    private String issuerKeyStoreResource;
    private String issuerAlias;
    private String rootCertificateResource;

    private CertificationAuthorityBuilder() {
    }

    public CertificationAuthorityBuilder setOrgName(String orgName) {
        this.orgName = orgName;
        return this;
    }

    public CertificationAuthorityBuilder setIssuerAlias(String issuerAlias) {
        this.issuerAlias = issuerAlias;
        return this;
    }

    public CertificationAuthorityBuilder setSystemKeyPassword(char[] systemKeyPassword) {
        this.systemKeyPassword = systemKeyPassword;
        return this;
    }

    public CertificationAuthorityBuilder setSystemKeyResource(String systemKeyResource) {
        this.systemKeyResource = systemKeyResource;
        return this;
    }

    public CertificationAuthorityBuilder setIssuerKeyStoreResource(String issuerKeyStoreResource) {
        this.issuerKeyStoreResource = issuerKeyStoreResource;
        return this;
    }

    public CertificationAuthorityBuilder setIssuerPasswordResource(String issuerPasswordResource) {
        this.issuerPasswordResource = issuerPasswordResource;
        return this;
    }

    public CertificationAuthorityBuilder setRootCertificateResource(String rootCertificateResource) {
        this.rootCertificateResource = rootCertificateResource;
        return this;
    }

    public CertificationAuthority build() throws IOException, CryptoException {
        return new CertificationAuthority(loadIssuerKeyStore(), orgName, loadRootCertificate());
    }

    private X509Certificate loadRootCertificate() throws IOException, CryptoException {
        return CertificateResourceLoader.loadCertificate(rootCertificateResource);
    }

    private char[] loadIssuerPassword() throws IOException, CryptoException {
        try (BufferedReader reader = getIssuerPasswordReader();
             BufferedReader systemKeyReader = getSystemKeyReader()) {
            return PKI.readPassword(systemKeyReader, systemKeyPassword, reader);
        }
    }

    private CertificateAndKey loadIssuerKeyStore() throws IOException, CryptoException {
        // Read and decrypt password of keystore
        char[] password = loadIssuerPassword();

        // Load key and certificate
        CertificateAndKey certificateAndKey;
        try (InputStream is = getIssuerKeyStoreInputStream()) {
            certificateAndKey = PKI.loadKeyStore(issuerAlias, is, password);
        }

        Arrays.fill(password, '*');
        return certificateAndKey;
    }

    private BufferedReader getSystemKeyReader() throws IOException {
        return ResourceLoader.getBufferedReaderForResource(systemKeyResource);
    }

    private BufferedReader getIssuerPasswordReader() throws IOException {
        return ResourceLoader.getBufferedReaderForResource(issuerPasswordResource);
    }

    private InputStream getIssuerKeyStoreInputStream() throws IOException {
        return ResourceLoader.getInputStreamForResource(issuerKeyStoreResource);
    }

}
