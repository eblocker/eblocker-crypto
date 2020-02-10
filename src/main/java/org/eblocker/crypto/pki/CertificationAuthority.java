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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

public class CertificationAuthority {

    @SuppressWarnings("unused")
    private static final Logger log = LoggerFactory.getLogger(CertificationAuthority.class);

    private final CertificateAndKey issuer;

    private final String orgName;

    private final X509Certificate root;

    CertificationAuthority(CertificateAndKey issuer, String orgName, X509Certificate root) {
        this.issuer = issuer;
        this.orgName = orgName;
        this.root = root;
        if (issuer == null ||issuer.getCertificate() == null ||issuer.getKey() == null) {
            throw new IllegalArgumentException("Cannot build CA without issuer key and certificate");
        }
    }

    public X509Certificate issueCertificate(X509Certificate request, String name, Date notValidAfter) throws CryptoException {
        return PKI.generateTLSClientCertificate(request, orgName, name, notValidAfter, issuer);
    }

    public X509Certificate getIssuerCertificate() {
        return issuer.getCertificate();
    }

    public X509Certificate getRootCertificate() {
        return root;
    }

    public X509CRL issueCrl(List<RevocationInfo> revocationInfos, int days) throws CryptoException {
        return PKI.generateCrl(revocationInfos, issuer, new Date(new Date().getTime() + 1000L * 3600 * 24 * days));
    }

}
