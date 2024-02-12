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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import org.eblocker.crypto.CryptoException;
import org.eblocker.crypto.CryptoService;
import org.eblocker.crypto.CryptoServiceFactory;
import org.eblocker.crypto.keys.SystemKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class JsonEncryptionModuleTest {

    private static Path systemKeyPath;
    private static CryptoService cryptoService;
    private ObjectMapper objectMapper;

    @BeforeAll
    static void setupCryptoService() throws CryptoException, IOException {
        // Generate a temporary system key storage location in a portable way
        // but it must no exist upon initialization of SystemKey or else it'll be
        // read and initialization fails.
        systemKeyPath = Files.createTempFile("unit-test-system-", ".key");
        Files.delete(systemKeyPath);

        SystemKey systemKey = new SystemKey(systemKeyPath.toString());
        cryptoService = CryptoServiceFactory.getInstance().setKey(systemKey.get()).build();
    }

    @AfterAll
    static void tearDownCryptoService() throws IOException {
        if (Files.exists(systemKeyPath)) {
            Files.delete(systemKeyPath);
        }
    }

    @BeforeEach
    void setupObjectMapper() throws IOException, CryptoException {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JsonEncryptionModule(objectMapper, cryptoService));
    }

    @Test
    void testRegularSerializationSimplePojo() throws IOException {
        SimplePojo a = new SimplePojo(100, "hello, world!");
        SimplePojo b = deserialize(serialize(a), SimplePojo.class);

        assertEquals(a.getIntValue(), b.getIntValue());
        assertEquals(a.getStringValue(), b.getStringValue());
    }

    @Test
    void testEncryptedClassSerializationSimplePojo() throws IOException {
        objectMapper.registerModule(new MixInModule(SimplePojo.class, EncryptClassMixIn.class));

        SimplePojo a = new SimplePojo(100, "hello, world!");
        byte[] serialized = serialize(a);

        // ensure class has been completely serialized as string
        JsonNode node = objectMapper.readTree(serialized);
        assertEquals(JsonNodeType.STRING, node.getNodeType());
        assertFalse(node.asText().contains("hello, world!"));

        // deserialize and check properties have been decrypted
        SimplePojo b = deserialize(serialize(a), SimplePojo.class);
        assertEquals(a.getIntValue(), b.getIntValue());
        assertEquals(a.getStringValue(), b.getStringValue());
    }

    @Test
    public void testEncryptSinglePropertySimplePojo() throws IOException {
        objectMapper.registerModule(new MixInModule(SimplePojo.class, EncryptIntValue.class));

        SimplePojo a = new SimplePojo(100, "hello, world!");
        byte[] serialized = serialize(a);

        // check resulting json is an object
        JsonNode node = objectMapper.readTree(serialized);
        assertEquals(JsonNodeType.OBJECT, node.getNodeType());

        // intValue must be encrypted
        assertNotNull(node.findValue("intValue"));
        assertEquals(JsonNodeType.STRING, node.findValue("intValue").getNodeType());

        // stringValue must be unencrypted
        assertNotNull(node.findValue("stringValue"));
        assertEquals(JsonNodeType.STRING, node.findValue("stringValue").getNodeType());
        assertEquals("hello, world!", node.findValue("stringValue").asText());

        // deserialize and check properties have been decrypted
        SimplePojo b = deserialize(serialize(a), SimplePojo.class);
        assertEquals(a.getIntValue(), b.getIntValue());
        assertEquals(a.getStringValue(), b.getStringValue());
    }

    @Test
    public void testEncryptClassAndSinglePropertySimplePojo() throws IOException {
        objectMapper.registerModule(new MixInModule(SimplePojo.class, EncryptClassMixIn.class));
        objectMapper.registerModule(new MixInModule(SimplePojo.class, EncryptIntValue.class));

        SimplePojo a = new SimplePojo(100, "hello, world!");
        byte[] serialized = serialize(a);

        // ensure class has been completely serialized as string
        JsonNode node = objectMapper.readTree(serialized);
        assertEquals(JsonNodeType.STRING, node.getNodeType());
        assertFalse(node.asText().contains("hello, world!"));

        // deserialize and check properties have been decrypted
        SimplePojo b = deserialize(serialize(a), SimplePojo.class);
        assertEquals(a.getIntValue(), b.getIntValue());
        assertEquals(a.getStringValue(), b.getStringValue());
    }


    @Test
    public void testEncryptPojoHierachy() throws IOException {
        objectMapper.registerModule(new MixInModule(ContainerPojo.class, EncryptClassMixIn.class));

        ContainerPojo containerPojo = new ContainerPojo(100, "this is a container");
        SimplePojo innerPojo = new SimplePojo(200, "hello, world!");
        containerPojo.setPojo(innerPojo);
        byte[] serialized = serialize(containerPojo);

        // ensure class has been completely serialized as string
        JsonNode node = objectMapper.readTree(serialized);
        assertEquals(JsonNodeType.STRING, node.getNodeType());
        assertFalse(node.asText().contains("hello, world!"));
        assertFalse(node.asText().contains("this is a container"));

        // deserialize and check properties have been decrypted
        ContainerPojo deserializedContainer = deserialize(serialized, ContainerPojo.class);
        assertEquals(containerPojo.getIntValue(), deserializedContainer.getIntValue());
        assertEquals(containerPojo.getStringValue(), deserializedContainer.getStringValue());
        assertNotNull(deserializedContainer.getPojo());
        assertEquals(innerPojo.getIntValue(), deserializedContainer.getPojo().getIntValue());
        assertEquals(innerPojo.getStringValue(), deserializedContainer.getPojo().getStringValue());
    }

    private byte[] serialize(Object o) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        objectMapper.writeValue(baos, o);
        return baos.toByteArray();
    }

    private <T> T deserialize(byte[] serialized, Class<T> targetClass) throws IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(serialized);
        return objectMapper.readValue(bais, targetClass);
    }

    private static class SimplePojo {
        private Integer intValue;
        private String stringValue;

        public SimplePojo() {
        }

        public SimplePojo(Integer intValue, String stringValue) {
            this.intValue = intValue;
            this.stringValue = stringValue;
        }

        public Integer getIntValue() {
            return intValue;
        }

        public String getStringValue() {
            return stringValue;
        }
    }

    private static class ContainerPojo extends SimplePojo {
        private SimplePojo pojo;

        @SuppressWarnings("unused")
        public ContainerPojo() {
        }

        public ContainerPojo(Integer intValue, String stringValue) {
            super(intValue, stringValue);
        }

        public SimplePojo getPojo() {
            return pojo;
        }

        public void setPojo(SimplePojo pojo) {
            this.pojo = pojo;
        }
    }


    private static class MixInModule extends SimpleModule {
        private Class targetClass;
        private Class[] mixIns;

        public MixInModule(Class targetClass, Class... mixIns) {
            this.targetClass = targetClass;
            this.mixIns = mixIns;
        }

        @Override
        public void setupModule(SetupContext context) {
            for(Class mixIn : mixIns) {
                context.setMixInAnnotations(targetClass, mixIn);
            }
        }
    }

    @JsonEncrypt
    private abstract static class EncryptClassMixIn {
    }

    private abstract static class EncryptIntValue {
        @JsonEncrypt
        public abstract int getIntValue();
    }
}