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
package org.eblocker.crypto.util;

import org.eblocker.crypto.CryptoException;
import org.eblocker.crypto.pki.PKI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class CertificateResourceLoader extends ResourceLoader {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateResourceLoader.class);

    public static X509Certificate loadCertificate(String certificateResource) throws IOException, CryptoException {
        return PKI.loadCertificate(ResourceLoader.getInputStreamForResource(certificateResource));
    }

    public static List<X509Certificate> loadCertificates(String directoryResource, String extension) throws IOException {
        List<X509Certificate> certificates = new ArrayList<>();
        InputStream dir = getInputStreamForResource(directoryResource);
        BufferedReader reader = new BufferedReader(new InputStreamReader(dir));
        String resource;
        while ((resource = reader.readLine()) != null) {
            if (resource.endsWith(extension)) {
                try {
                    certificates.add(PKI.loadCertificate(getInputStreamForResource(directoryResource + resource)));
                } catch (CryptoException e) {
                    LOG.warn("Cannot load certificate resource {}: {}", resource, e.getMessage());
                }
            }
        }
        return certificates;
    }

}
