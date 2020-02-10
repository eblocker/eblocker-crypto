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
import org.eblocker.crypto.EncryptedData;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.ResolvableDeserializer;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

public class DecryptingDeserializer extends StdDeserializer implements ResolvableDeserializer {

    private Class beanClass;
    private JsonDeserializer deserializer;
    private ObjectMapper objectMapper;
    private CryptoService cryptoService;

    public DecryptingDeserializer(Class beanClass, JsonDeserializer deserializer, ObjectMapper objectMapper, CryptoService cryptoService) {
        super(beanClass);
        this.beanClass = beanClass;
        this.deserializer = deserializer;
        this.objectMapper = objectMapper;
        this.cryptoService = cryptoService;
    }

    @Override
    public Object deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        if (jsonParser.getCurrentToken() == JsonToken.VALUE_STRING) {
            try {
                EncryptedData data = deserializeEncryptedData(jsonParser.getBinaryValue());
                ByteArrayInputStream is = new ByteArrayInputStream(cryptoService.decrypt(data));
                return objectMapper.readValue(is, beanClass);
            } catch (CryptoException e) {
                throw new JsonParseException("failed decryption", jsonParser.getCurrentLocation(), e);
            }
        } else {
            return deserializer.deserialize(jsonParser, deserializationContext);
        }
    }

    @Override
    public void resolve(DeserializationContext deserializationContext) throws JsonMappingException {
        ((ResolvableDeserializer) deserializer).resolve(deserializationContext);
    }

    private EncryptedData deserializeEncryptedData(byte[] encrypted) throws IOException {
        DataInputStream encryptedStream = new DataInputStream(new ByteArrayInputStream(encrypted));
        byte[] initializationVector = readBytes(encryptedStream);
        byte[] cipherText = readBytes(encryptedStream);

        EncryptedData data = new EncryptedData(initializationVector, cipherText);
        return data;
    }

    private byte[] readBytes(DataInputStream is) throws IOException {
        byte[] bytes = new byte[is.readInt()];
        is.read(bytes);
        return bytes;
    }
}

