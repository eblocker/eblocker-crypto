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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ResourceLoader {

    ResourceLoader() {
    }

    public static InputStream getInputStreamForResource(String resource) throws IOException {
        if (resource.startsWith("classpath:")) {
            return ResourceLoader.class.getClassLoader().getResourceAsStream(resource.substring("classpath:".length()));
        } else {
            String path = resource.startsWith("file:") ? resource.substring("file:".length()) : resource;
            if (Files.isDirectory(Paths.get(path))) {
                //
                // This is certainly not the most elegant way of reading files from a directory.
                // However, we want to return an InputStream of file names,
                // just as ClassLoader.getResourceAsStream() is doing it.
                // So that we can use the same method for classpath and file system resources.
                //
                StringBuilder s = new StringBuilder();
                DirectoryStream<Path> dir = Files.newDirectoryStream(Paths.get(path));
                dir.forEach(f -> s.append(f.toAbsolutePath().getFileName().toString()).append("\n"));
                dir.close();
                return new ByteArrayInputStream(s.toString().getBytes(StandardCharsets.UTF_8));

            } else {
                return Files.newInputStream(Paths.get(path));
            }
        }
    }

    public static BufferedReader getBufferedReaderForResource(String resource) throws IOException {
        return new BufferedReader(new InputStreamReader(getInputStreamForResource(resource)));
    }

}
