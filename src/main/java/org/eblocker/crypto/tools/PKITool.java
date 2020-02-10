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
package org.eblocker.crypto.tools;

import org.eblocker.crypto.CryptoException;
import org.eblocker.crypto.pki.CertificateAndKey;
import org.eblocker.crypto.pki.PKI;
import org.eblocker.crypto.util.DateUtil;
import org.apache.commons.cli.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Scanner;

public class PKITool {

    private static final PKITool app = new PKITool();

    public static void main(String[] args) throws Exception {
        app.init(args);
        app.run();
    }

    private static final String ORG_NAME = "eBlocker GmbH";
    private static final int KEY_SIZE = 2048;

    private static final String KEYSTORE_EXT = ".jks";
    private static final String PKCS12_EXT = ".p12";
    private static final String KEY_EXT = ".key";
    private static final String CERTIFICATE_EXT = ".crt";
    private static final String PASSWORD_EXT = ".properties";
    private static final String CRL_EXT = ".crl";

    private enum Command {
        //           -o     -v     -n     -k     -i     -a     -t     -b
        //           out    valid  name   sysKey in     alias  root   rootA
        SYSTEMKEY   (true,  false, false, false, false, false, false, false),
        ROOT        (true,  true,  true,  true,  false, false, false, false),
        CA          (true,  true,  true,  true,  true,  true,  false, false),
        DEVICE      (true,  true,  true,  true,  true,  true,  false, false),
        REQUEST     (true,  false, true,  true,  false, false, false, false),
        SHOWPASSWORD(false, false, false, true,  true,  false, false, false),
        LOADKEYSTORE(false, false, false, true,  true,  true,  false, false),
        TLSSERVER   (true,  true,  true,  true,  true,  true,  true,  true ),
        TLSCLIENT   (true,  true,  true,  true,  true,  true,  true,  true ),
        CRL         (true,  true,  false, true,  true,  true,  false, false),
        ;

        private final boolean needsOutput;
        private final boolean needsValidity;
        private final boolean needsName;
        private final boolean needsSystemKey;
        private final boolean needsInput;
        private final boolean needsAlias;
        private final boolean needsRoot;
        private final boolean needsRootAlias;

        Command(boolean needsOutput, boolean needsValidity, boolean needsName, boolean needsSystemKey, boolean needsInput, boolean needsAlias, boolean needsRoot, boolean needsRootAlias) {
            this.needsOutput = needsOutput;
            this.needsValidity = needsValidity;
            this.needsName = needsName;
            this.needsSystemKey = needsSystemKey;
            this.needsInput = needsInput;
            this.needsAlias = needsAlias;
            this.needsRoot = needsRoot;
            this.needsRootAlias = needsRootAlias;
        }

    }

    private Command command;
    private String out;
    private int validity;
    private String name;
    private String systemKey;
    private String in;
    private String alias;
    private String root;
    private String rootAlias;

    private PKI pki;

    private char[] masterPassword = null;

    private void init(String[] args) throws ParseException {

        CommandLine commandLine = getCommandLine(args);
        command = null;
        if (commandLine.hasOption("s")) {
            command = Command.SYSTEMKEY;
        } else if (commandLine.hasOption("r")) {
            command = Command.ROOT;
        } else if (commandLine.hasOption("c")) {
            command = Command.CA;
        } else if (commandLine.hasOption("d")) {
            command = Command.DEVICE;
        } else if (commandLine.hasOption("g")) {
            command = Command.REQUEST;
        } else if (commandLine.hasOption("p")) {
            command = Command.SHOWPASSWORD;
        } else if (commandLine.hasOption("l")) {
            command = Command.LOADKEYSTORE;
        } else if (commandLine.hasOption("x")) {
            command = Command.TLSSERVER;
        } else if (commandLine.hasOption("y")) {
            command = Command.TLSCLIENT;
        } else if (commandLine.hasOption("z")) {
            command = Command.CRL;
        }
        if (command == null) usage(null);

        if (command.needsOutput) {
            if (!commandLine.hasOption("o")) usage("o");
            out = commandLine.getOptionValue("o");
        }
        if (command.needsValidity) {
            if (!commandLine.hasOption("v")) usage("v");
            validity = ((Number) commandLine.getParsedOptionValue("v")).intValue();
        }
        if (command.needsName) {
            if (!commandLine.hasOption("n")) usage("n");
            name = commandLine.getOptionValue("n");
        }
        if (command.needsSystemKey) {
            if (!commandLine.hasOption("k")) usage("k");
            systemKey = commandLine.getOptionValue("k");
        }
        if (command.needsInput) {
            if (!commandLine.hasOption("i")) usage("i");
            in = commandLine.getOptionValue("i");
        }
        if (command.needsAlias) {
            if (!commandLine.hasOption("a")) usage("a");
            alias = commandLine.getOptionValue("a");
        }
        if (command.needsRoot) {
            if (!commandLine.hasOption("t")) usage("t");
            root = commandLine.getOptionValue("t");
        }
        if (command.needsRootAlias) {
            if (!commandLine.hasOption("b")) usage("b");
            rootAlias = commandLine.getOptionValue("b");
        }
    }

    private void run() throws CryptoException, IOException {

        switch (command) {

            case SYSTEMKEY:
                generateSystemKey();
                System.out.println("Wrote new system key to "+Paths.get(out).toString());
                break;

            case ROOT:
                generateRoot();
                System.out.println("Wrote new root certificate and key to " + Paths.get(out).toString());
                break;

            case CA:
                generateL1CA();
                System.out.println("Wrote new L1 CA certificate and key to " + Paths.get(out).toString());
                break;

            case DEVICE:
                signDeviceCertificate();
                System.out.println("Wrote new device certificate to " + Paths.get(out).toString());
                break;

            case TLSSERVER:
                signTLSServerCertificate();
                System.out.println("Wrote new TLS server certificate to " + Paths.get(out).toString());
                break;

            case TLSCLIENT:
                signTLSClientCertificate();
                System.out.println("Wrote new TLS client certificate to " + Paths.get(out).toString());
                break;

            case REQUEST:
                generateDeviceRequest();
                System.out.println("Wrote new certificate request and key to " + Paths.get(out).toString());
                break;

            case SHOWPASSWORD:
                char[] password = loadPassword(in);
                System.out.println("Password="+new String(password));
                break;

            case LOADKEYSTORE:
                CertificateAndKey certificateAndKey = loadKeyStore(in, alias);
                System.out.println("Certificate: "+certificateAndKey.getCertificate());
                System.out.println("Key: "+certificateAndKey.getKey());
                break;

            case CRL:
                generateRootCrl();
                System.out.println("Wrote new CRL to " + Paths.get(out).toString());
                break;

        }

    }

    private void generateSystemKey() throws IOException, CryptoException {
        char[] systemKeyPassword = getSystemKeyPassword();
        BufferedWriter writer = getWriter(out+PASSWORD_EXT);
        pki.generateSystemKey(writer, systemKeyPassword);
        writer.close();
    }

    private void generateRoot() throws IOException, CryptoException {
        // Generate self signed root certificate
        CertificateAndKey root = pki.generateRoot(ORG_NAME, name, validity, KEY_SIZE);

        // Generate password and store it encrypted with system key
        char[] password = generateAndStorePassword(out);
        //System.out.println("Password=" + new String(password));

        // Store root certificate and key in keytore, protected with password
        generateAndStoreKeyStore(root, name, password, out, "JKS");
        storeCertificate(root, out);
    }

    private void generateL1CA() throws IOException, CryptoException {
        // Load root key and certificate
        CertificateAndKey root = loadKeyStore(in, alias);

        // Generate L1CA certificate and key
        CertificateAndKey l1ca = pki.generateL1CA(ORG_NAME, name, validity, KEY_SIZE, root);

        // Generate password and store it encrypted with system key
        char[] password = generateAndStorePassword(out);
        //System.out.println("Password=" + new String(password));

        // Store L1CA certificate and key in keytore, protected with password
        generateAndStoreKeyStore(l1ca, name, password, out, "JKS");
        storeCertificate(l1ca, out);
    }

    private void generateDeviceRequest() throws IOException, CryptoException {
        // Generate password and store it encrypted with system key
        char[] password = generateAndStorePassword(out);

        CertificateAndKey deviceRequest = pki.generateSelfSignedCertificateRequest(name, KEY_SIZE);

        // Store device key in keytore, protected with password; store certificate request in PEM file
        generateAndStoreKeyStore(deviceRequest, name, password, out, "JKS");
        storeCertificate(deviceRequest, out);
        storeKey(deviceRequest, out);
    }

    private void generateRootCrl() throws IOException, CryptoException {
        // Load root key and certificate
        CertificateAndKey root = loadKeyStore(in, alias);

        X509CRL crl = pki.generateCrl(Collections.emptyList(), root, DateUtil.addYears(new Date(), validity));

        // Store device key in keytore, protected with password; store certificate request in PEM file
        storeCrl(crl, out);
    }

    private void signDeviceCertificate() throws IOException, CryptoException {
        // Generate password and store it encrypted with system key
        char[] password = loadPassword(out);

        CertificateAndKey deviceRequest = loadKeyStore(out, name);
        CertificateAndKey l1ca = loadKeyStore(in, alias);

        CertificateAndKey deviceCertificate = new CertificateAndKey(
                pki.generateSignedCertificate(deviceRequest.getCertificate(), ORG_NAME, name, DateUtil.addYears(new Date(), validity), l1ca),
                deviceRequest.getKey());

        // Store device key in keytore, protected with password; store certificate request in PEM file
        generateAndStoreKeyStore(deviceCertificate, name, password, out, "JKS");
        storeCertificate(deviceCertificate, out);
    }

    private void signTLSServerCertificate() throws IOException, CryptoException {
        // Generate password and store it encrypted with system key
        char[] password = generateAndStorePassword(out);

        CertificateAndKey request = pki.generateSelfSignedCertificateRequest(name, KEY_SIZE);

        CertificateAndKey l1ca = loadKeyStore(in, alias);

        CertificateAndKey issuedCertificate = new CertificateAndKey(
                pki.generateTLSServerCertificate(request.getCertificate(), ORG_NAME, name, DateUtil.addYears(new Date(), validity), l1ca),
                request.getKey());

        CertificateAndKey rootca = loadKeyStore(root, rootAlias);

        // Store device key in keytore, protected with password; store certificate in PEM file
        generateAndStoreKeyStore(issuedCertificate, name, password, out, "JKS", l1ca.getCertificate(), rootca.getCertificate());
        storeCertificate(issuedCertificate, out);
        storeKey(issuedCertificate, out);
    }

    private void signTLSClientCertificate() throws IOException, CryptoException {
        // Generate password and store it encrypted with system key
        char[] password = generateAndStorePassword(out);

        CertificateAndKey request = pki.generateSelfSignedCertificateRequest(name, KEY_SIZE);

        CertificateAndKey l1ca = loadKeyStore(in, alias);

        CertificateAndKey issuedCertificate = new CertificateAndKey(
                pki.generateTLSClientCertificate(request.getCertificate(), ORG_NAME, name, DateUtil.addYears(new Date(), validity), l1ca),
                request.getKey());

        CertificateAndKey rootca = loadKeyStore(root, rootAlias);

        // Store device key in keytore, protected with password; store certificate in PEM file
        generateAndStoreKeyStore(issuedCertificate, name, password, out, "JKS", l1ca.getCertificate(), rootca.getCertificate());
        generateAndStoreKeyStore(issuedCertificate, name, password, out, "PKCS12", l1ca.getCertificate(), rootca.getCertificate());
        storeCertificate(issuedCertificate, out);
    }

    private char[] generateAndStorePassword(String out) throws IOException, CryptoException {
        char[] systemKeyPassword = getSystemKeyPassword();
        BufferedReader systemKeyReader = getReader(systemKey + PASSWORD_EXT);
        BufferedWriter passwordWriter = getWriter(out + PASSWORD_EXT);
        char[] password = pki.generatePassword(systemKeyReader, systemKeyPassword, passwordWriter);
        passwordWriter.close();
        systemKeyReader.close();
        return password;
    }

    private char[] loadPassword(String in) throws IOException, CryptoException {
        char[] systemKeyPassword = getSystemKeyPassword();
        BufferedReader reader = getReader(in+PASSWORD_EXT);
        BufferedReader systemKeyReader = getReader(systemKey + PASSWORD_EXT);
        char[] password = pki.readPassword(systemKeyReader, systemKeyPassword, reader);
        reader.close();
        return password;
    }

    private void generateAndStoreKeyStore(CertificateAndKey certificateAndKey, String name, char[] password, String out, String keyStoreType, X509Certificate...chain) throws IOException, CryptoException {
        OutputStream os = getOutputStream(out + (keyStoreType.equals("PKCS12") ? PKCS12_EXT : KEYSTORE_EXT));
        System.out.println("Creating keyStore with password '"+new String(password)+"'");
        pki.generateKeyStore(certificateAndKey, name, password, os, keyStoreType, chain);
        os.close();
    }

    private CertificateAndKey loadKeyStore(String in, String alias) throws IOException, CryptoException {
        // Read and decrypt password of keystore
        char[] password = loadPassword(in);

        // Load key and certificate
        InputStream is = getInputStream(in+KEYSTORE_EXT);
        CertificateAndKey certificateAndKey = pki.loadKeyStore(alias, is, password);
        is.close();

        return certificateAndKey;
    }

    private void storeCertificate(CertificateAndKey certificateAndKey, String out) throws IOException, CryptoException {
        OutputStream os = getOutputStream(out + CERTIFICATE_EXT);
        pki.storeCertificate(certificateAndKey.getCertificate(), os);
        os.close();
    }

    private void storeKey(CertificateAndKey certificateAndKey, String out) throws IOException, CryptoException {
        OutputStream os = getOutputStream(out + KEY_EXT);
        pki.storePrivateKey(certificateAndKey.getKey(), os);
        os.close();
    }

    private void storeCrl(X509CRL crl, String out) throws IOException, CryptoException {
        OutputStream os = getOutputStream(out + CRL_EXT);
        pki.storeCrl(crl, os);
        os.close();
    }

    private char[] getSystemKeyPassword() {
        if (masterPassword == null) {
            if (System.console() != null) {
                masterPassword = System.console().readPassword("%s", "Enter master password:");
            } else {
                try (Scanner scanner = new Scanner(System.in)) {
                    System.out.println("Enter master password (*** INSECURE ***):");
                    String password = scanner.nextLine();
                    masterPassword = password.toCharArray();
                }
            }
        }
        return Arrays.copyOf(masterPassword, masterPassword.length);
    }

    private OutputStream getOutputStream(String path) throws IOException {
        return Files.newOutputStream(Paths.get(path));
    }

    private InputStream getInputStream(String path) throws IOException {
        return Files.newInputStream(Paths.get(path));
    }

    private BufferedWriter getWriter(String path) throws IOException {
        return Files.newBufferedWriter(Paths.get(path));
    }

    private BufferedReader getReader(String path) throws IOException {
        return Files.newBufferedReader(Paths.get(path));
    }

    private Options getOptions() {
        Options options = new Options();

        options.addOption(Option.builder("s").longOpt("generateSystemKey").desc("generate system key, requires -o").build());
        options.addOption(Option.builder("r").longOpt("generateRoot").desc("generate root, requires -o, -v, -n, -k").build());
        options.addOption(Option.builder("c").longOpt("generateCA").desc("generate L1 CA, requires -o, -v, -n, -k, i, -a").build());
        options.addOption(Option.builder("d").longOpt("signDevice").desc("sign device certificate, requires -o, -v, -n, -k, i, -a").build());
        options.addOption(Option.builder("g").longOpt("generateRequest").desc("generate PKCS#10 request, requires -o, -n, -k").build());
        options.addOption(Option.builder("p").longOpt("showPassword").desc("show password, requires -i, -k").build());
        options.addOption(Option.builder("l").longOpt("loadKeyStore").desc("load keyStore, requires -i, -k, -a").build());
        options.addOption(Option.builder("x").longOpt("tlsServer").desc("sign TLS server certificate, requires -o, -v, -n, -k, i, -a").build());
        options.addOption(Option.builder("y").longOpt("tlsClient").desc("sign TLS client certificate, requires -o, -v, -n, -k, i, -a").build());
        options.addOption(Option.builder("z").longOpt("generateCRL").desc("sign CRL, requires -o, -v, -n, -k, i, -a").build());

        options.addOption(Option.builder("o").longOpt("out").desc("output file name").type(String.class).hasArg().build());
        options.addOption(Option.builder("i").longOpt("in").desc("input file name").type(String.class).hasArg().build());
        options.addOption(Option.builder("v").longOpt("validity").desc("validity in years").type(Number.class).hasArg().build());
        options.addOption(Option.builder("n").longOpt("name").desc("CN and alias of new certificate").type(String.class).hasArg().build());
        options.addOption(Option.builder("a").longOpt("alias").desc("alias of signer certificate").type(String.class).hasArg().build());
        options.addOption(Option.builder("k").longOpt("systemKey").desc("system key file name").type(String.class).hasArg().build());
        options.addOption(Option.builder("t").longOpt("root").desc("root file name").type(String.class).hasArg().build());
        options.addOption(Option.builder("b").longOpt("rootAlias").desc("alias of root certificate").type(String.class).hasArg().build());

        return options;
    }

    private CommandLine getCommandLine(String[] args) throws ParseException {
        CommandLineParser parser = new DefaultParser();
        return parser.parse(getOptions(), args);
    }

    private void usage(String option) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp(option, getOptions());
        System.exit(1);
    }

}
