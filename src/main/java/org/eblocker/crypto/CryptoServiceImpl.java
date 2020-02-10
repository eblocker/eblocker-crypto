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
package org.eblocker.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;

public class CryptoServiceImpl implements CryptoService {

    private static final Logger log = LoggerFactory.getLogger(CryptoServiceImpl.class);

    private final SecureRandom random = new SecureRandom();

    private final Key key;

    private final String cipherTransformation;

    public CryptoServiceImpl(Key key, String cipherTransformation) {
        this.key = key;
        this.cipherTransformation = cipherTransformation;
    }

    @Override
    public EncryptedData encrypt(byte[] data) throws CryptoException {
        Cipher cipher = createCipher();
        byte[] initializationVector = new byte[cipher.getBlockSize()];
        random.nextBytes(initializationVector);

        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(initializationVector));

        } catch (GeneralSecurityException e) {
            String msg = "Cannot initialize encryption cipher: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);

        }

        byte[] cipherText;
        try {
            cipherText = cipher.doFinal(data);

        } catch (GeneralSecurityException e) {
            String msg = "Cannot encrypt data: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);

        }

        return new EncryptedData(initializationVector, cipherText);
    }

    @Override
    public byte[] decrypt(EncryptedData encryptedData) throws CryptoException {
        Cipher cipher = createCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encryptedData.getInitializationVector()));

        } catch (GeneralSecurityException e) {
            String msg = "Cannot initialize decryption cipher: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);

        }
        try {
            return cipher.doFinal(encryptedData.getCipherText());

        } catch (GeneralSecurityException e) {
            String msg = "Cannot decrypt data: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);

        }
    }

    private Cipher createCipher() throws CryptoException {
        try {
            return Cipher.getInstance(cipherTransformation);

        } catch (GeneralSecurityException e) {
            String msg = "Cannot initialize encryption service: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }
    }
}
