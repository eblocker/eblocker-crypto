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
import org.eblocker.crypto.CryptoServiceFactory;
import org.eblocker.crypto.EncryptedData;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;

import static org.junit.Assert.*;

public class KeyHandlerTest {

    private final SecureRandom random = new SecureRandom();

    private static final Charset CHARSET = StandardCharsets.UTF_8;

    private byte[] defaultMasterKey = generateMasterKey(16);

    @Test
    public void testStoreAndLoadKey() throws Exception {
        byte[] key = KeyHandler.createKey();

        StringWriter writer = new StringWriter();
        KeyHandler.storeKey(key, new BufferedWriter(writer), getCryptoService());

        String properties = writer.toString();
        System.out.println(properties);

        StringReader reader = new StringReader(properties);
        byte[] loadedKey = KeyHandler.loadKey(new BufferedReader(reader), getCryptoService());

        assertArrayEquals(key, loadedKey);
    }

    @Test
    public void testUseKey() throws Exception {
        //
        // Generate key
        //
        byte[] key = KeyHandler.createKey();
        System.out.println("created key=" + Hex.encodeHexString(key));

        //
        // Store encrypted key
        //
        StringWriter writer = new StringWriter();
        KeyHandler.storeKey(key, new BufferedWriter(writer), getCryptoService());
        String properties = writer.toString();
        System.out.println(properties);

        //
        // Encrypt data with key
        //
        String plainText = "Hello World!";
        EncryptedData encryptedData = getCryptoService(key).encrypt(plainText.getBytes(CHARSET));

        //
        // Read encrypted key
        //
        StringReader reader = new StringReader(properties);
        byte[] loadedKey = KeyHandler.loadKey(new BufferedReader(reader), getCryptoService());
        System.out.println("loaded key="+ Hex.encodeHexString(loadedKey));

        //
        // Decrypt data with decrypted key
        //
        String decryptedText = new String(getCryptoService(loadedKey).decrypt(encryptedData), CHARSET);
        assertEquals(plainText, decryptedText);

    }

    @Test(expected=CryptoException.class)
    public void testUseKey_invalidIV() throws Exception {
        //
        // Generate key
        //
        byte[] key = KeyHandler.createKey();

        //
        // Store encrypted key
        //
        StringWriter writer = new StringWriter();
        KeyHandler.storeKey(key, new BufferedWriter(writer), getCryptoService());

        //
        // Modify IV
        //
        Properties properties = new Properties();
        properties.load(new StringReader(writer.toString()));
        properties.setProperty(KeyHandler.IV_PROP_KEY, "xyz");
        writer = new StringWriter();
        properties.store(writer, "");

        //
        // Read encrypted key
        //
        StringReader reader = new StringReader(writer.toString());
        @SuppressWarnings("unused")
        byte[] loadedKey = KeyHandler.loadKey(new BufferedReader(reader), getCryptoService());
    }

    @Test(expected=CryptoException.class)
    public void testUseKey_invalidKey() throws Exception {
        //
        // Generate key
        //
        byte[] key = KeyHandler.createKey();

        //
        // Store encrypted key
        //
        StringWriter writer = new StringWriter();
        KeyHandler.storeKey(key, new BufferedWriter(writer), getCryptoService());

        //
        // Modify IV
        //
        Properties properties = new Properties();
        properties.load(new StringReader(writer.toString()));
        properties.setProperty(KeyHandler.KEY_PROP_KEY, "xyz");
        writer = new StringWriter();
        properties.store(writer, "");

        //
        // Read encrypted key
        //
        StringReader reader = new StringReader(writer.toString());
        @SuppressWarnings("unused")
        byte[] loadedKey = KeyHandler.loadKey(new BufferedReader(reader), getCryptoService());
    }

    private CryptoService getCryptoService() throws CryptoException {
        return CryptoServiceFactory.getInstance().setKey(Arrays.copyOf(defaultMasterKey, defaultMasterKey.length)).build();
    }

    private CryptoService getCryptoService(byte[] key) throws CryptoException {
        return CryptoServiceFactory.getInstance().setKey(key).build();
    }

    @Test
    public void testConstructorIsPrivate() throws Exception {
        Constructor<KeyHandler> constructor = KeyHandler.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(constructor.getModifiers()));
        constructor.setAccessible(true);
        constructor.newInstance();
    }

    private byte[] generateMasterKey(int keyLength) {
        byte[] masterKey = new byte[keyLength];
        random.nextBytes(masterKey);
        return masterKey;
    }

}