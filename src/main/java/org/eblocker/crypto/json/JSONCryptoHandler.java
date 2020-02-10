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
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;

public class JSONCryptoHandler {

    private static final ObjectMapper mapper = new ObjectMapper();

    private JSONCryptoHandler() {
    }

    public static <T> T decrypt(Class<T> clazz, CryptoService cryptoService, InputStream in) throws CryptoException, IOException {
        EncryptedData encryptedData = mapper.readValue(in, EncryptedData.class);
        byte[] data = cryptoService.decrypt(encryptedData);
        return mapper.readValue(new ByteArrayInputStream(data), clazz);
    }

    public static <T> void encrypt(T data, CryptoService cryptoService, OutputStream out) throws CryptoException, IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        mapper.writeValue(baos, data);
        EncryptedData encryptedData = cryptoService.encrypt(baos.toByteArray());
        mapper.writeValue(out, encryptedData);
    }

}
