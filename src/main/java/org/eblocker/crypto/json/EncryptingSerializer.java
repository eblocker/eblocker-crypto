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
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class EncryptingSerializer extends JsonSerializer {
    private JsonSerializer serializer;
    private CryptoService cryptoService;

    public EncryptingSerializer(JsonSerializer<?> serializer, CryptoService cryptoService) {
        this.serializer = serializer;
        this.cryptoService = cryptoService;
    }

    @Override
    public void serialize(Object o, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        try {
            byte[] serializedObject = serializeObject(o, jsonGenerator, serializerProvider);
            EncryptedData data = cryptoService.encrypt(serializedObject);
            byte[] encrypted = serializeEncryptedData(data);
            jsonGenerator.writeBinary(encrypted);
        } catch (CryptoException e) {
            throw new JsonGenerationException("failed to encrypt " + o, e);
        }
    }

    private byte[] serializeEncryptedData(EncryptedData data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(data.getInitializationVector().length);
        dos.write(data.getInitializationVector());
        dos.writeInt(data.getCipherText().length);
        dos.write(data.getCipherText());
        dos.flush();
        return baos.toByteArray();
    }

    private byte[] serializeObject(Object o, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        JsonGenerator capturingGenerator = jsonGenerator.getCodec().getFactory().createGenerator(baos);
        serializer.serialize(o, capturingGenerator, serializerProvider);
        capturingGenerator.flush();
        return baos.toByteArray();
    }
}
