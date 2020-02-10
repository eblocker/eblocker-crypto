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

import org.eblocker.crypto.CryptoService;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter;
import com.fasterxml.jackson.databind.ser.impl.PropertySerializerMap;

public class EncryptingBeanPropertyWriter extends BeanPropertyWriter {

    private CryptoService cryptoService;

    public EncryptingBeanPropertyWriter(BeanPropertyWriter writer, CryptoService cryptoService) {
        super(writer);

        this.cryptoService = cryptoService;

        if (_serializer != null) {
            _serializer = new EncryptingSerializer(_serializer, cryptoService);
        }
    }

    @Override
    public void assignSerializer(JsonSerializer<Object> ser) {
        super.assignSerializer(ser);
        _serializer = new EncryptingSerializer(_serializer, cryptoService);
    }

    @Override
    protected JsonSerializer<Object> _findAndAddDynamic(PropertySerializerMap map, Class<?> type, SerializerProvider provider) throws JsonMappingException {
        JsonSerializer<Object> serializer = super._findAndAddDynamic(map, type, provider);
        if (serializer != null) {
            return new EncryptingSerializer(serializer, cryptoService);
        }
        return serializer;
    }

}