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
package org.eblocker.crypto.util;

import org.junit.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class EncodingUtilTest {

    @Test
    public void test() {

        testEncoding("Hello World");

    }

    private void testEncoding(String msg) {
        char[] chars = msg.toCharArray();
        byte[] bytes = EncodingUtil.toBytes(chars);
        assertEquals(msg, new String(bytes, StandardCharsets.UTF_8));

        bytes = msg.getBytes(StandardCharsets.UTF_8);
        chars = EncodingUtil.toChars(bytes);
        assertEquals(msg, new String(chars));
    }

    @Test
    public void testConstructorIsPrivate() throws Exception {
        Constructor<EncodingUtil> constructor = EncodingUtil.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(constructor.getModifiers()));
        constructor.setAccessible(true);
        constructor.newInstance();
    }

}
