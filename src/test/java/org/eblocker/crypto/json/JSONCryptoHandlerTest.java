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
package org.eblocker.crypto.json;

import org.eblocker.crypto.CryptoException;
import org.eblocker.crypto.CryptoService;
import org.eblocker.crypto.CryptoServiceFactory;
import org.eblocker.crypto.keys.SystemKey;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JSONCryptoHandlerTest {

    @Test
    void test() throws IOException, CryptoException {
        Path tmp = Files.createTempFile("encrypted.", ".data");
        if (Files.exists(tmp)) {
            Files.delete(tmp);
        }
        SystemKey systemKey = new SystemKey(tmp.toString());
        CryptoService cryptoService = CryptoServiceFactory.getInstance().setKey(systemKey.get()).build();

        TestEntity entity = new TestEntity("that", 4711, new Date());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        JSONCryptoHandler.encrypt(entity, cryptoService, out);

        System.out.println(out.toString());

        ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
        TestEntity entity2 = JSONCryptoHandler.decrypt(TestEntity.class, cryptoService, in);

        assertNotNull(entity2);
        assertEquals(entity.getWhat(), entity2.getWhat());
        assertEquals(entity.getHowmuch(), entity2.getHowmuch());
        assertEquals(entity.getWhen(), entity2.getWhen());
    }

    @Test
    void testConstructorIsPrivate() throws Exception {
        Constructor<JSONCryptoHandler> constructor = JSONCryptoHandler.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(constructor.getModifiers()));
        constructor.setAccessible(true);
        constructor.newInstance();
    }

}