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
package org.eblocker.crypto.keys;

import org.eblocker.crypto.CryptoException;
import org.eblocker.crypto.CryptoServiceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class SystemKey implements KeyWrapper {

    private static final Logger log = LoggerFactory.getLogger(SystemKey.class);

    private static final Charset CHARSET = StandardCharsets.UTF_8;

    private static final byte[] DEFAULT_MASTERKEY = new byte[]{
            -121, -117, 41, -73, -127, 94, -55, -18, 57, 7, 30, 63, -100, 64, 117, -57,
            //-35, -56, -5, -75, -99, -105, -64, 103, -88, 0, 44, 18, 115, 25, -70, -55
    };

    private final String systemKeyPath;

    private byte[] masterKey = DEFAULT_MASTERKEY;
    private byte[] systemKey = null;

    public SystemKey(String systemKeyPath) {
        this.systemKeyPath = systemKeyPath;
        initialize();
    }

    private void initialize() {
        if (!Files.exists(Paths.get(systemKeyPath))) {
            create();
            store();

        } else if (Files.isRegularFile(Paths.get(systemKeyPath))) {
            load();

        }
        if (systemKey == null) {
            log.error("Have no valid system key. Cannot decrypt/encrypt critical system data. Will anyway try to continue.");
        }
    }

    @Override
    public byte[] get() {
        return systemKey;
    }

    private void create() {
        systemKey = KeyHandler.createKey();
    }

    private void store() {
        BufferedWriter writer;
        try {
            writer = Files.newBufferedWriter(Paths.get(systemKeyPath), CHARSET, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);

        } catch (IOException e) {
            String msg = "Cannot open system key file "+systemKeyPath+" for writing: "+e.getMessage();
            log.error(msg);
            systemKey = null;
            return;
        }
        try {
            KeyHandler.storeKey(systemKey, writer, CryptoServiceFactory.getInstance().setKey(masterKey).build());

        } catch (IOException|CryptoException e) {
            String msg = "Cannot write system key file "+systemKeyPath+": "+e.getMessage();
            log.error(msg);
            systemKey = null;
            return;
        }
    }

    private void load() {
        BufferedReader reader;
        try {
            reader = Files.newBufferedReader(Paths.get(systemKeyPath));

        } catch (IOException e) {
            String msg = "Cannot open system key file "+systemKeyPath+" for reading: "+e.getMessage();
            log.error(msg);
            systemKey = null;
            return;
        }
        try {
            systemKey = KeyHandler.loadKey(reader, CryptoServiceFactory.getInstance().setKey(masterKey).build());
            //
            // Fail safe: In rare cases, the system key file exist, but is empty or corrupted.
            // This might happen, if the first startup process is aborted at the wrong point in time.
            // Treat this, as if the file does not exist at all.
            //
            if (systemKey == null) {
                create();
                store();
            }

        } catch (IOException|CryptoException e) {
            String msg = "Cannot read system key file "+systemKeyPath+": "+e.getMessage();
            log.error(msg);
            systemKey = null;
            return;
        }
    }

}
