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

import org.eblocker.crypto.util.EncodingUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class CryptoServiceFactory {

    private static final Logger log = LoggerFactory.getLogger(CryptoServiceFactory.class);

    private static final String DEFAULT_KEY_TYPE = "AES";
    private static final String DEFAULT_CIPHER = "AES/CBC/PKCS5Padding";
    private static final String KEY_DERIVATION_FUNCTION = "PBKDF2WithHmacSHA256";
    public static final int KEY_DERIVATION_COUNT = 20000;
    public static final int DERIVED_KEY_LENGTH = 256;

    private byte[] bytes = null;
    private String keyType = DEFAULT_KEY_TYPE;

    @SuppressWarnings("unused")
    private String cipher = DEFAULT_CIPHER;

    private CryptoServiceFactory() {
    }

    public static CryptoServiceFactory getInstance() {
        return new CryptoServiceFactory();
    }

    public CryptoService build() throws CryptoException {
        if (bytes == null) {
            String msg = "Cannot build crypto service without key";
            log.error(msg);
            throw new CryptoException(msg);
        }
        return new CryptoServiceImpl(createKey(), cipher);
    }

    public CryptoServiceFactory setKeyType(String keyType) {
        this.keyType = keyType;
        return this;
    }

    public CryptoServiceFactory setCipher(String cipher) {
        this.cipher = cipher;
        return this;
    }

    public CryptoServiceFactory setKey(byte[] bytes) {
        this.bytes = bytes;
        return this;
    }

    /**
     * @deprecated Use setSaltedPassword() instead
     */
    public CryptoServiceFactory setPassword(char[] password) {
        bytes = EncodingUtil.toBytes(password);
        return this;
    }

    public CryptoServiceFactory setSaltedPassword(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_FUNCTION);
        KeySpec spec = new PBEKeySpec(password, salt, KEY_DERIVATION_COUNT, DERIVED_KEY_LENGTH);
        bytes = factory.generateSecret(spec).getEncoded();
        return this;
    }

    private Key createKey() {
        Key key = new SecretKeySpec(bytes, keyType);
        return key;
    }
}
