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
package org.eblocker.crypto.keys;

import org.eblocker.crypto.CryptoException;
import org.eblocker.crypto.CryptoService;
import org.eblocker.crypto.EncryptedData;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Properties;

public class KeyHandler {

    private static final Logger log = LoggerFactory.getLogger(KeyHandler.class);

    private static final int KEY_LENGTH = 16;

    /* package private */ static final String IV_PROP_KEY = "u";
    /* package private */ static final String KEY_PROP_KEY = "v";

    private static final SecureRandom random = new SecureRandom();

    private KeyHandler() {
    }

    public static byte[] createKey() {
        byte[] key = new byte[KEY_LENGTH];
        random.nextBytes(key);
        return key;
    }

    public static void storeKey(byte[] key, BufferedWriter writer, CryptoService cryptoService) throws IOException, CryptoException {
        Properties properties = new Properties();

        EncryptedData encryptedData = cryptoService.encrypt(key);

        properties.put(IV_PROP_KEY, Hex.encodeHexString(encryptedData.getInitializationVector()));
        properties.put(KEY_PROP_KEY, Hex.encodeHexString(encryptedData.getCipherText()));

        properties.store(writer, Hex.encodeHexString(createKey()));
    }

    public static byte[] loadKey(BufferedReader reader, CryptoService cryptoService) throws IOException, CryptoException {
        Properties properties = new Properties();
        properties.load(reader);

        // Failsafe, if file is empty or corrupted
        if (properties.getProperty(IV_PROP_KEY) == null || properties.getProperty(KEY_PROP_KEY) == null) {
            return null;
        }

        byte[] initializationVector;
        try {
            initializationVector = Hex.decodeHex(properties.getProperty(IV_PROP_KEY).toCharArray());

        } catch (DecoderException e) {
            String msg = "Cannot decode property "+IV_PROP_KEY+" of key file: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }

        byte[] encryptedKey;
        try {
            encryptedKey = Hex.decodeHex(properties.getProperty(KEY_PROP_KEY).toCharArray());

        } catch (DecoderException e) {
            String msg = "Cannot decode property "+KEY_PROP_KEY+" of key file: "+e.getMessage();
            log.error(msg);
            throw new CryptoException(msg, e);
        }

        byte[] key = cryptoService.decrypt(new EncryptedData(initializationVector, encryptedKey));
        return key;
    }


}
