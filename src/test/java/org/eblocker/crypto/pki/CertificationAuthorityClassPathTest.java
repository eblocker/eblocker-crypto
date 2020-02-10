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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.Assert.*;

public class CertificationAuthorityClassPathTest {

    private static final String ORG_NAME = "eBlocker GmbH";

    private static final String ISSUER_NAME = "eBlocker Device CA I";
    private static final String ISSUER_ALIAS = ISSUER_NAME;

    private static final int KEY_SIZE = 2048;

    private static char[] SYSTEM_KEY_PASSWORD = "hY7*ZoQ93!5@x0Ql4aKRBNaArzNKyxTN".toCharArray();
    private List<char[]> passwords = new ArrayList<>();

    private String systemKeyPath = "classpath:systemkey.properties";
    private String issuerKeyPasswordPath = "classpath:l1ca.properties";
    private String issuerKeyStorePath = "classpath:l1ca.jks";
    private String rootCertificatePath = "classpath:root.crt";

    @Before
    public void init() throws IOException, CryptoException {
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
                setOrgName(ORG_NAME).
                setIssuerAlias(ISSUER_ALIAS).
                setSystemKeyResource(systemKeyPath).
                setSystemKeyPassword(getSystemKeyPassword()).
                setIssuerPasswordResource(issuerKeyPasswordPath).
                setIssuerKeyStoreResource(issuerKeyStorePath).
                setRootCertificateResource(rootCertificatePath).
                build();

        assertNotNull(ca);

        Date notValidAfter = DateUtil.addYears(new Date(), 1);
        X509Certificate deviceCertificate = ca.issueCertificate(request.getCertificate(), "My Device", notValidAfter);

        assertNotNull(deviceCertificate);
        assertTrue(PKI.verifyCertificateSignature(deviceCertificate, ca.getIssuerCertificate()));

        //System.out.println(deviceCertificate);
    }

    private char[] getSystemKeyPassword() {
        char[] copy = Arrays.copyOf(SYSTEM_KEY_PASSWORD, SYSTEM_KEY_PASSWORD.length);
        passwords.add(copy);
        return copy;
    }

}