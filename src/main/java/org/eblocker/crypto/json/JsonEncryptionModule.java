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
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonEncryptionModule extends Module {

    private ObjectMapper objectMapper;
    private CryptoService cryptoService;

    public JsonEncryptionModule(ObjectMapper objectMapper, CryptoService cryptoService) {
        this.objectMapper = objectMapper;
        this.cryptoService = cryptoService;
    }

    @Override
    public String getModuleName() {
        return "custom";
    }

    @Override
    public Version version() {
        return new Version(0, 1, 0, "snapshot", "group", "artifact");
    }

    @Override
    public void setupModule(SetupContext setupContext) {
        setupContext.addBeanDeserializerModifier(new DecryptingDeserializerModifier(objectMapper, cryptoService));
        setupContext.addBeanSerializerModifier(new EncryptingSerializerModifier(cryptoService));
    }
}
