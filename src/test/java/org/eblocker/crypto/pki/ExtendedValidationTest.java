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

import static org.junit.Assert.*;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.Test;

public class ExtendedValidationTest {
	@Test
	public void test() throws Exception {
		checkExtendedValidation("Postbank",      true);
		checkExtendedValidation("Haspa",         true);
		checkExtendedValidation("DomainFACTORY", true);
		checkExtendedValidation("Google",        false);
		checkExtendedValidation("eBlocker",      false);
	}

	private void checkExtendedValidation(String name, boolean extendedValidationExpected) throws Exception {
		X509Certificate serverCert = readCert(name, 0);
		X509Certificate rootCert   = readCert(name, 2);
		
		assertEquals(
				name + " has an extended validation certificate?",
				extendedValidationExpected,
				ExtendedValidation.isExtendedValidationCertificate(serverCert, rootCert)
		);
	}

	private X509Certificate readCert(String name, int index) throws Exception {
		String filename = "extended-validation-tests/" + name + "_" + index + ".crt";
		InputStream inStream = ClassLoader.getSystemResourceAsStream(filename);
		if (inStream == null) {
			throw new Exception("Could not find " + filename);
		}
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
		return cert;
	}

}
