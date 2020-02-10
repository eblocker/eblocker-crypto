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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

import org.eblocker.crypto.CryptoException;

/**
 * Checks whether a certificate is an Extended Validation (EV) certificate.
 *
 */
public class ExtendedValidation {

	/**
	 * Checks if the certificate contains any of the known extended validation OIDs in
	 * the policy identifier.
	 * 
	 * @param certificate the certificate to check
	 * @param rootCert the root certificate of the chain
	 * @return true, if the certificate is an extended validation (EV) certificate
	 * @throws CryptoException when the SHA-256 hash of the root certificate could not be determined
	 */
	public static boolean isExtendedValidationCertificate(X509Certificate certificate, X509Certificate rootCert) throws CryptoException {
		byte[] policyInformationValue = certificate.getExtensionValue("2.5.29.32");

		if (policyInformationValue == null) { // No policy extension
			return false;
		}

		String oidCert = null;
		try {
			ASN1OctetString policyInformationString = ASN1OctetString.getInstance(policyInformationValue);
			if (policyInformationString == null) {
				return false;
			}
			ASN1Sequence certificatePolicies = ASN1Sequence.getInstance(policyInformationString.getOctets());
			if (certificatePolicies == null || certificatePolicies.size() < 1) {
				return false;
			}
			ASN1Sequence policyInformation = (ASN1Sequence) certificatePolicies.getObjectAt(0);
			if (policyInformation == null || policyInformation.size() < 1) {
				return false;
			}
			ASN1ObjectIdentifier policyIdentifier = (ASN1ObjectIdentifier) policyInformation.getObjectAt(0);
			if (policyIdentifier == null) {
				return false;
			}
			oidCert = policyIdentifier.toString();
		} catch (Exception e) {
			return false; // Could not find the expected OID in the certificate
		}

		ExtendedValidationOID oidRoot = null;
		try {
			String sha256 = getSHA256Hash(rootCert);
			oidRoot = ExtendedValidationOID.oidByRootCertSHA256(sha256);
		} catch (CertificateEncodingException | NoSuchAlgorithmException e) {
			throw new CryptoException("Could not create SHA-256 hash of root certificate", e);
		}
		
		if (oidCert == null || oidRoot == null) {
			return false;
		}
		
		return oidCert.equals(oidRoot.getOID());
	}

	private static String getSHA256Hash(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(cert.getEncoded());
		String result = "";
		boolean first = true;
		for (byte b : hash) {
			if (first) {
				first = false;
			} else {
				result += ":";
			}
			result += String.format("%02X", b);
		}
		return result;
	}

}
