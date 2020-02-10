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
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializationConfig;
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter;
import com.fasterxml.jackson.databind.ser.BeanSerializerModifier;
import com.fasterxml.jackson.databind.type.ArrayType;
import com.fasterxml.jackson.databind.type.CollectionLikeType;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.fasterxml.jackson.databind.type.MapLikeType;
import com.fasterxml.jackson.databind.type.MapType;

import java.util.List;
import java.util.stream.Collectors;

public class EncryptingSerializerModifier extends BeanSerializerModifier {

    private CryptoService cryptoService;

    public EncryptingSerializerModifier(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @Override
    public List<BeanPropertyWriter> changeProperties(SerializationConfig config, BeanDescription beanDesc, List<BeanPropertyWriter> beanProperties) {
        return super.changeProperties(config, beanDesc, beanProperties).stream().map(pw -> {
            if (pw.getAnnotation(JsonEncrypt.class) != null) {
                return new EncryptingBeanPropertyWriter(pw, cryptoService);
            }
            return pw;
        }).collect(Collectors.toList());
    }

    @Override
    public JsonSerializer<?> modifySerializer(SerializationConfig config, BeanDescription beanDesc, JsonSerializer<?> serializer) {
        return wrap(beanDesc, super.modifySerializer(config, beanDesc, serializer));
    }

    @Override
    public JsonSerializer<?> modifyArraySerializer(SerializationConfig config, ArrayType valueType, BeanDescription beanDesc, JsonSerializer<?> serializer) {
        return wrap(beanDesc, super.modifyArraySerializer(config, valueType, beanDesc, serializer));
    }

    @Override
    public JsonSerializer<?> modifyCollectionSerializer(SerializationConfig config, CollectionType valueType, BeanDescription beanDesc, JsonSerializer<?> serializer) {
        return wrap(beanDesc, super.modifyCollectionSerializer(config, valueType, beanDesc, serializer));
    }

    @Override
    public JsonSerializer<?> modifyCollectionLikeSerializer(SerializationConfig config, CollectionLikeType valueType, BeanDescription beanDesc, JsonSerializer<?> serializer) {
        return wrap(beanDesc, super.modifyCollectionLikeSerializer(config, valueType, beanDesc, serializer));
    }

    @Override
    public JsonSerializer<?> modifyMapSerializer(SerializationConfig config, MapType valueType, BeanDescription beanDesc, JsonSerializer<?> serializer) {
        return wrap(beanDesc, super.modifyMapSerializer(config, valueType, beanDesc, serializer));
    }

    @Override
    public JsonSerializer<?> modifyMapLikeSerializer(SerializationConfig config, MapLikeType valueType, BeanDescription beanDesc, JsonSerializer<?> serializer) {
        return wrap(beanDesc, super.modifyMapLikeSerializer(config, valueType, beanDesc, serializer));
    }

    @Override
    public JsonSerializer<?> modifyEnumSerializer(SerializationConfig config, JavaType valueType, BeanDescription beanDesc, JsonSerializer<?> serializer) {
        return wrap(beanDesc, super.modifyEnumSerializer(config, valueType, beanDesc, serializer));
    }

    @Override
    public JsonSerializer<?> modifyKeySerializer(SerializationConfig config, JavaType valueType, BeanDescription beanDesc, JsonSerializer<?> serializer) {
        return wrap(beanDesc, super.modifyKeySerializer(config, valueType, beanDesc, serializer));
    }

    private JsonSerializer wrap(BeanDescription beanDesc, JsonSerializer<?> serializer) {
        if (beanDesc.getClassAnnotations().get(JsonEncrypt.class) != null) {
            return new EncryptingSerializer(serializer, cryptoService);
        }

        return serializer;
    }
}
