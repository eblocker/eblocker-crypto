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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.junit.Test;

public class DateUtilTest {

    private final DateFormat format = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss.SSS Z");

    @Test
    public void testAddYears() throws Exception {
        Date start    = format.parse("2015/08/01 19:09:12.789 +0200");
        Date expected = format.parse("2025/08/01 19:09:12.789 +0200");
        assertEquals(expected, DateUtil.addYears(start, 10));
    }

    @Test
    public void testStripMillis() throws Exception {
        Date start    = format.parse("2015/08/01 19:09:12.789 +0200");
        Date expected = format.parse("2015/08/01 19:09:12.000 +0200");
        assertEquals(expected, DateUtil.stripMillis(start, 0));
    }

    @Test
    public void testStripMillis_addSeconds() throws Exception {
        Date start    = format.parse("2015/08/01 19:09:12.789 +0200");
        Date expected = format.parse("2015/08/01 19:09:13.000 +0200");
        assertEquals(expected, DateUtil.stripMillis(start, 1));
    }

    @Test
    public void testConstructorIsPrivate() throws Exception {
        Constructor<DateUtil> constructor = DateUtil.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(constructor.getModifiers()));
        constructor.setAccessible(true);
        constructor.newInstance();
    }


}
