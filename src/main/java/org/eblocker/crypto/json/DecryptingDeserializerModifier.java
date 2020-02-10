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
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.BeanDeserializerBuilder;
import com.fasterxml.jackson.databind.deser.BeanDeserializerModifier;
import com.fasterxml.jackson.databind.deser.SettableBeanProperty;
import com.fasterxml.jackson.databind.type.ArrayType;
import com.fasterxml.jackson.databind.type.CollectionLikeType;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.fasterxml.jackson.databind.type.MapLikeType;
import com.fasterxml.jackson.databind.type.MapType;

import java.util.Iterator;

public class DecryptingDeserializerModifier extends BeanDeserializerModifier {

    private ObjectMapper objectMapper;
    private CryptoService cryptoService;

    public DecryptingDeserializerModifier(ObjectMapper objectMapper, CryptoService cryptoService) {
        this.objectMapper = objectMapper;
        this.cryptoService = cryptoService;
    }

    @Override
    public BeanDeserializerBuilder updateBuilder(DeserializationConfig config, BeanDescription beanDesc, BeanDeserializerBuilder builder) {
        Iterator<SettableBeanProperty> beanPropertyIterator = builder.getProperties();
        while (beanPropertyIterator.hasNext()) {
            SettableBeanProperty property = beanPropertyIterator.next();
            if (property.getAnnotation(JsonEncrypt.class) != null) {
                JsonDeserializer deserializer = property.getValueDeserializer();
                builder.addOrReplaceProperty(property.withValueDeserializer(new DecryptingDeserializer(property.getType().getRawClass(), deserializer, objectMapper, cryptoService)), true);
            }
        }
        return builder;
    }

    @Override
    public JsonDeserializer<?> modifyDeserializer(DeserializationConfig config, BeanDescription beanDesc, JsonDeserializer<?> deserializer) {
        return wrap(beanDesc, super.modifyDeserializer(config, beanDesc, deserializer));
    }

    @Override
    public JsonDeserializer<?> modifyArrayDeserializer(DeserializationConfig config, ArrayType valueType, BeanDescription beanDesc, JsonDeserializer<?> deserializer) {
        return wrap(beanDesc, super.modifyArrayDeserializer(config, valueType, beanDesc, deserializer));
    }

    @Override
    public JsonDeserializer<?> modifyCollectionDeserializer(DeserializationConfig config, CollectionType type, BeanDescription beanDesc, JsonDeserializer<?> deserializer) {
        return wrap(beanDesc, super.modifyCollectionDeserializer(config, type, beanDesc, deserializer));
    }

    @Override
    public JsonDeserializer<?> modifyCollectionLikeDeserializer(DeserializationConfig config, CollectionLikeType type, BeanDescription beanDesc, JsonDeserializer<?> deserializer) {
        return wrap(beanDesc, super.modifyCollectionLikeDeserializer(config, type, beanDesc, deserializer));
    }

    @Override
    public JsonDeserializer<?> modifyMapDeserializer(DeserializationConfig config, MapType type, BeanDescription beanDesc, JsonDeserializer<?> deserializer) {
        return wrap(beanDesc, super.modifyMapDeserializer(config, type, beanDesc, deserializer));
    }

    @Override
    public JsonDeserializer<?> modifyMapLikeDeserializer(DeserializationConfig config, MapLikeType type, BeanDescription beanDesc, JsonDeserializer<?> deserializer) {
        return wrap(beanDesc, super.modifyMapLikeDeserializer(config, type, beanDesc, deserializer));
    }

    @Override
    public JsonDeserializer<?> modifyEnumDeserializer(DeserializationConfig config, JavaType type, BeanDescription beanDesc, JsonDeserializer<?> deserializer) {
        return wrap(beanDesc, super.modifyEnumDeserializer(config, type, beanDesc, deserializer));
    }

    private JsonDeserializer wrap(BeanDescription beanDesc, JsonDeserializer<?> deserializer) {
        if (beanDesc.getClassAnnotations().get(JsonEncrypt.class) != null) {
            return new DecryptingDeserializer(beanDesc.getBeanClass(), deserializer, objectMapper, cryptoService);
        }

        return deserializer;
    }
}
