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

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.Assert.*;

public class CryptoServiceTest {

    private final SecureRandom random = new SecureRandom();

    private final Charset CHARSET = StandardCharsets.UTF_8;

    private byte[] defaultMasterKey = generateMasterKey(16);

    @Test
    public void test() throws CryptoException {
        doTest(getCryptoService(), "Hello World");
        doTest(getCryptoService(), getCryptoService(), "Hello World");

        doTest(getCryptoService(), "Hello World, this is a very long strong with some non ASCII characters line 'äöüÄÖÜß'");

        doTest(getCryptoService(generateMasterKey(16)), "Hello World");
    }

    @Test(expected = CryptoException.class)
    public void test_fail_different_keys() throws CryptoException {
        String plainText = "Hello World";
        CryptoService encryptionService = getCryptoService(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});
        CryptoService decryptionService = getCryptoService(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0});

        decryptionService.decrypt(encryptionService.encrypt(plainText.getBytes(CHARSET)));
    }

    @Test
    public void testThreadSafety() throws CryptoException {
        CryptoService service = getCryptoService();

        Stream.of("Can we encrypt", "and decrypt", "this in parallel", "please?")
                .parallel()
                .forEach(str -> {
                    try {
                        EncryptedData encrypted = service.encrypt(str.getBytes());
                        byte[] decrypted = service.decrypt(encrypted);
                        assertEquals(str, new String(decrypted));
                    } catch (CryptoException e) {
                        fail("Could not encrypt/decrypt in parallel: " + e.getMessage());
                    }
                });
    }

    @Test
    public void testSaltedPassword() throws Exception {
        byte[] data = new byte[1234];
        random.nextBytes(data);
        char[] password = "top secret password".toCharArray();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        CryptoService service = CryptoServiceFactory.getInstance().setSaltedPassword(password, salt).build();
        EncryptedData encrypted = service.encrypt(data);
        assertArrayEquals(data, service.decrypt(encrypted));
    }

    private CryptoService getCryptoService() throws CryptoException {
        return CryptoServiceFactory.getInstance().setKey(Arrays.copyOf(defaultMasterKey, defaultMasterKey.length)).build();
    }

    private CryptoService getCryptoService(byte[] key) throws CryptoException {
        return CryptoServiceFactory.getInstance().setKey(key).build();
    }

    private void doTest(CryptoService encryptionService, String plainText) throws CryptoException {
        doTest(encryptionService, encryptionService, plainText);
    }

    private void doTest(CryptoService encryptionService, CryptoService decryptionService, String plainText) throws CryptoException {
        EncryptedData encryptedData = encryptionService.encrypt(plainText.getBytes(CHARSET));
        assertNotNull(encryptedData);
        assertNotNull(encryptedData.getCipherText());
        assertNotNull((encryptedData.getInitializationVector()));

        System.out.println("Plain text:  "+Hex.encodeHexString(plainText.getBytes(CHARSET)));
        System.out.println("Cipher text: "+Hex.encodeHexString(encryptedData.getCipherText()));
        System.out.println("Ini. vector: "+Hex.encodeHexString(encryptedData.getInitializationVector()));

        byte[] decryptedText = decryptionService.decrypt(encryptedData);

        System.out.println("Decrypted:   "+Hex.encodeHexString(decryptedText));

        assertEquals(plainText, new String(decryptedText, CHARSET));
    }

    private byte[] generateMasterKey(int keyLength) {
        byte[] masterKey = new byte[keyLength];
        random.nextBytes(masterKey);
        return masterKey;
    }
}