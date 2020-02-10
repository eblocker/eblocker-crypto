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

import org.junit.Test;

import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class CertificateResourceLoaderTest {

    private String rootCertificatePath = "classpath:root.crt";
    private String sampleCertificateDir = "classpath:extended-validation-tests/";
    private String sampleCertificateExt = "_0.crt";

    @Test
    public void testResourceLoader_classPath() throws Exception {
        doTestCertificateResourceLoader(
                rootCertificatePath,
                sampleCertificateDir,
                sampleCertificateExt
        );
    }

    @Test
    public void testResourceLoader_fileSystem() throws Exception {
        //
        // Convert the classpath resources to file system resources.
        // We do this to avoid problems with paths in different test environments.
        // This way, we can always be sure that the files are found.
        //
        doTestCertificateResourceLoader(
                convertClassPathResourceToFile(rootCertificatePath),
                convertClassPathResourceToFile(sampleCertificateDir),
                sampleCertificateExt
        );
    }

    private void doTestCertificateResourceLoader(String singleResource, String directoryResource, String pattern) throws Exception {
        X509Certificate cert = CertificateResourceLoader.loadCertificate(singleResource);
        assertNotNull(cert);

        List<X509Certificate> certs = CertificateResourceLoader.loadCertificates(directoryResource, pattern);
        assertEquals(5, certs.size());
    }

    private String convertClassPathResourceToFile(String resource) throws URISyntaxException {
        String classPathResource = resource.substring("classpath:".length());
        Path path = Paths.get(ClassLoader.getSystemResource(classPathResource).toURI()).toAbsolutePath();
        boolean directory = Files.isDirectory(path);
        String fileResource = "file:" + path.toString() + (directory ? "/" : "");
        System.out.println(classPathResource + " -> " + fileResource);
        return fileResource;
    }
}