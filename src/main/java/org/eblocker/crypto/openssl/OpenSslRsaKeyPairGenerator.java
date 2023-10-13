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
package org.eblocker.crypto.openssl;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public class OpenSslRsaKeyPairGenerator extends KeyPairGenerator {
    private int keySize;

    public OpenSslRsaKeyPairGenerator() {
        super("RSA");
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.keySize = keysize;
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            String command = "openssl genrsa " + keySize;
            Process process = Runtime.getRuntime().exec(command);
            process.waitFor();
            try (PEMParser parser = new PEMParser(new InputStreamReader(process.getInputStream()))) {
                Object pemObject = parser.readObject();
                if (pemObject == null) {
                    throw new OpenSslRsaKeyPairGeneratorException("Could not read PEM object from call: " + command);
                }
                PEMKeyPair pemKeyPair;
                if (pemObject instanceof PEMKeyPair) {
                    pemKeyPair = (PEMKeyPair) pemObject;
                } else if (pemObject instanceof PrivateKeyInfo) {
                    pemKeyPair = getPemKeyPair((PrivateKeyInfo) pemObject);
                } else {
                    throw new OpenSslRsaKeyPairGeneratorException("Could not convert generated RSA key. Expected either PEMKeyPair or PrivateKeyInfo, but got " + pemObject.getClass());
                }
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                return converter.getKeyPair(pemKeyPair);
            }
        } catch (IOException | InterruptedException e) {
            throw new OpenSslRsaKeyPairGeneratorException("Failed to generate RSA key", e);
        }
    }

    /**
     * OpenSSL 3 writes PKCS#8 instead of PKCS#1.
     * We convert the PrivateKeyInfo returned by the PEMParser to a PEMKeyPair.
     */
    private PEMKeyPair getPemKeyPair(PrivateKeyInfo privateKeyInfo) throws IOException {
        RSAPrivateKey privateKey = RSAPrivateKey.getInstance(privateKeyInfo.parsePrivateKey());
        RSAPublicKey publicKey = new RSAPublicKey(privateKey.getModulus(), privateKey.getPublicExponent());
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
        return new PEMKeyPair(new SubjectPublicKeyInfo(algorithmIdentifier, publicKey), new PrivateKeyInfo(algorithmIdentifier, privateKey));
    }

    public class OpenSslRsaKeyPairGeneratorException extends RuntimeException {
        public OpenSslRsaKeyPairGeneratorException(String message) {
            super(message);
        }
        public OpenSslRsaKeyPairGeneratorException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
