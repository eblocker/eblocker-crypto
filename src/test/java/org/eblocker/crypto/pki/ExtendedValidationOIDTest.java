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

import java.util.regex.Pattern;

import org.junit.Test;

/**
 * Some sanity checks for the ExtendedValidationOID enum
 */
public class ExtendedValidationOIDTest {
	public static final Pattern SHA256_PATTERN = Pattern.compile("([0-9A-F]{2}:){31}[0-9A-F]{2}");
	public static final Pattern OID_PATTERN = Pattern.compile("(\\d+\\.)+\\d+");
	
	@Test
	public void testHashes() {
		for (ExtendedValidationOID oid : ExtendedValidationOID.values()) {
			assertTrue("Hash of " + oid + " matches pattern?", SHA256_PATTERN.matcher(oid.getRootCertSHA256()).matches());
			assertTrue("OID of " + oid + " matches pattern?", OID_PATTERN.matcher(oid.getOID()).matches());
		}
	}

}
