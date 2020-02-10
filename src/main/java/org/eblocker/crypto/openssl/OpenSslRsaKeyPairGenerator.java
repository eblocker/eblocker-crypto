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
            Process process = Runtime.getRuntime().exec("openssl genrsa " + keySize);
            process.waitFor();
            try (PEMParser parser = new PEMParser(new InputStreamReader(process.getInputStream()))) {
                Object o = parser.readObject();
                PEMKeyPair pemKeyPair = (PEMKeyPair) o;
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                return converter.getKeyPair(pemKeyPair);
            }
        } catch (IOException | InterruptedException e) {
            throw new OpenSslRsaKeyPairGeneratorException("failed to generate rsa key", e);
        }
    }

    public class OpenSslRsaKeyPairGeneratorException extends RuntimeException {
        public OpenSslRsaKeyPairGeneratorException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
