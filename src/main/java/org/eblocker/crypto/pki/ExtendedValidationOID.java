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
package org.eblocker.crypto.pki;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * This enum contains the object IDs for extended validation policy identifiers.
 * 
 * Source: http://hg.mozilla.org/mozilla-central/raw-file/tip/security/certverifier/ExtendedValidation.cpp
 *
 */
public enum ExtendedValidationOID {
    // OU=Security Communication EV RootCA1,O="SECOM Trust Systems CO.,LTD.",C=JP
    SECOM_EV_OID("1.2.392.200091.100.721.1", "A2:2D:BA:68:1E:97:37:6E:2D:39:7D:72:8A:AE:3A:9B:62:96:B9:FD:BA:60:BC:2E:11:F6:47:F2:C6:75:FB:37"),

    // CN=Cybertrust Global Root,O=Cybertrust, Inc
    Cybertrust_EV_OID("1.3.6.1.4.1.6334.1.100.1", "96:0A:DF:00:63:E9:63:56:75:0C:29:65:DD:0A:08:67:DA:0B:9C:BD:6E:77:71:4A:EA:FB:23:49:AB:39:3D:A3"),

    // CN=SwissSign Gold CA - G2,O=SwissSign AG,C=CH
    SwissSign_EV_OID("2.16.756.1.89.1.2.1.1", "62:DD:0B:E9:B9:F5:0A:16:3E:A0:F8:E7:5C:05:3B:1E:CA:57:EA:55:C8:68:8F:64:7C:68:81:F2:C8:35:7B:95"),

    // CN=StartCom Certification Authority,OU=Secure Digital Certificate Signing,O=StartCom Ltd.,C=IL
    StartCom_EV_OID("1.3.6.1.4.1.23223.1.1.1", "C7:66:A9:BE:F2:D4:07:1C:86:3A:31:AA:49:20:E8:13:B2:D1:98:60:8C:B7:B7:CF:E2:11:43:B8:36:DF:09:EA"),

    // CN=StartCom Certification Authority,OU=Secure Digital Certificate Signing,O=StartCom Ltd.,C=IL
    StartCom_EV_OID_2("1.3.6.1.4.1.23223.1.1.1", "E1:78:90:EE:09:A3:FB:F4:F4:8B:9C:41:4A:17:D6:37:B7:A5:06:47:E9:BC:75:23:22:72:7F:CC:17:42:A9:11"),

    // CN=StartCom Certification Authority G2,O=StartCom Ltd.,C=IL
    StartCom_EV_OID_3("1.3.6.1.4.1.23223.1.1.1", "C7:BA:65:67:DE:93:A7:98:AE:1F:AA:79:1E:71:2D:37:8F:AE:1F:93:C4:39:7F:EA:44:1B:B7:CB:E6:FD:59:95"),

    // CN=VeriSign Class 3 Public Primary Certification Authority - G5,OU="(c) 2006 VeriSign, Inc. - For authorized use only",OU=VeriSign Trust Network,O="VeriSign, Inc.",C=US
    VeriSign_EV_OID("2.16.840.1.113733.1.7.23.6", "9A:CF:AB:7E:43:C8:D8:80:D0:6B:26:2A:94:DE:EE:E4:B4:65:99:89:C3:D0:CA:F1:9B:AF:64:05:E4:1A:B7:DF"),

    // CN=GeoTrust Primary Certification Authority,O=GeoTrust Inc.,C=US
    GeoTrust_EV_OID("1.3.6.1.4.1.14370.1.6", "37:D5:10:06:C5:12:EA:AB:62:64:21:F1:EC:8C:92:01:3F:C5:F8:2A:E9:8E:E5:33:EB:46:19:B8:DE:B4:D0:6C"),

    // CN=thawte Primary Root CA,OU="(c) 2006 thawte, Inc. - For authorized use only",OU=Certification Services Division,O="thawte, Inc.",C=US
    Thawte_EV_OID("2.16.840.1.113733.1.7.48.1", "8D:72:2F:81:A9:C1:13:C0:79:1D:F1:36:A2:96:6D:B2:6C:95:0A:97:1D:B4:6B:41:99:F4:EA:54:B7:8B:FB:9F"),

    // CN=XRamp Global Certification Authority,O=XRamp Security Services Inc,OU=www.xrampsecurity.com,C=US
    Trustwave_EV_OID("2.16.840.1.114404.1.1.2.4.1", "CE:CD:DC:90:50:99:D8:DA:DF:C5:B1:D2:09:B7:37:CB:E2:C1:8C:FB:2C:10:C0:FF:0B:CF:0D:32:86:FC:1A:A2"),

    // CN=SecureTrust CA,O=SecureTrust Corporation,C=US
    Trustwave_EV_OID_2("2.16.840.1.114404.1.1.2.4.1", "F1:C1:B5:0A:E5:A2:0D:D8:03:0E:C9:F6:BC:24:82:3D:D3:67:B5:25:57:59:B4:E7:1B:61:FC:E9:F7:37:5D:73"),

    // CN=Secure Global CA,O=SecureTrust Corporation,C=US
    Trustwave_EV_OID_3("2.16.840.1.114404.1.1.2.4.1", "42:00:F5:04:3A:C8:59:0E:BB:52:7D:20:9E:D1:50:30:29:FB:CB:D4:1C:A1:B5:06:EC:27:F1:5A:DE:7D:AC:69"),

    // CN=COMODO ECC Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
    Comodo_EV_OID("1.3.6.1.4.1.6449.1.2.1.5.1", "17:93:92:7A:06:14:54:97:89:AD:CE:2F:8F:34:F7:F0:B6:6D:0F:3A:E3:A3:B8:4D:21:EC:15:DB:BA:4F:AD:C7"),

    // CN=COMODO Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
    Comodo_EV_OID_2("1.3.6.1.4.1.6449.1.2.1.5.1", "0C:2C:D6:3D:F7:80:6F:A3:99:ED:E8:09:11:6B:57:5B:F8:79:89:F0:65:18:F9:80:8C:86:05:03:17:8B:AF:66"),

    // CN=AddTrust External CA Root,OU=AddTrust External TTP Network,O=AddTrust AB,C=SE
    Comodo_EV_OID_3("1.3.6.1.4.1.6449.1.2.1.5.1", "68:7F:A4:51:38:22:78:FF:F0:C8:B1:1F:8D:43:D5:76:67:1C:6E:B2:BC:EA:B4:13:FB:83:D9:65:D0:6D:2F:F2"),

    // CN=UTN-USERFirst-Hardware,OU=http://www.usertrust.com,O=The USERTRUST Network,L=Salt Lake City,ST=UT,C=US
    Comodo_EV_OID_4("1.3.6.1.4.1.6449.1.2.1.5.1", "6E:A5:47:41:D0:04:66:7E:ED:1B:48:16:63:4A:A3:A7:9E:6E:4B:96:95:0F:82:79:DA:FC:8D:9B:D8:81:21:37"),

    // OU=Go Daddy Class 2 Certification Authority,O=\"The Go Daddy Group, Inc.\",C=US
    Go_Daddy_EV_OID_a("2.16.840.1.114413.1.7.23.3", "C3:84:6B:F2:4B:9E:93:CA:64:27:4C:0E:C6:7C:1E:CC:5E:02:4F:FC:AC:D2:D7:40:19:35:0E:81:FE:54:6A:E4"),

    // CN=Go Daddy Root Certificate Authority - G2,O="GoDaddy.com, Inc.",L=Scottsdale,ST=Arizona,C=US
    Go_Daddy_EV_OID_a_2("2.16.840.1.114413.1.7.23.3", "45:14:0B:32:47:EB:9C:C8:C5:B4:F0:D7:B5:30:91:F7:32:92:08:9E:6E:5A:63:E2:74:9D:D3:AC:A9:19:8E:DA"),

    // OU=Starfield Class 2 Certification Authority,O=\"Starfield Technologies, Inc.\",C=US
    Go_Daddy_EV_OID_b("2.16.840.1.114414.1.7.23.3", "14:65:FA:20:53:97:B8:76:FA:A6:F0:A9:95:8E:55:90:E4:0F:CC:7F:AA:4F:B7:C2:C8:67:75:21:FB:5F:B6:58"),

    // CN=Starfield Root Certificate Authority - G2,O="Starfield Technologies, Inc.",L=Scottsdale,ST=Arizona,C=US
    Go_Daddy_EV_OID_b_2("2.16.840.1.114414.1.7.23.3", "2C:E1:CB:0B:F9:D2:F9:E1:02:99:3F:BE:21:51:52:C3:B2:DD:0C:AB:DE:1C:68:E5:31:9B:83:91:54:DB:B7:F5"),

    // CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
    DigiCert_EV_OID("2.16.840.1.114412.2.1", "74:31:E5:F4:C3:C1:CE:46:90:77:4F:0B:61:E0:54:40:88:3B:A9:A0:1E:D0:0B:A6:AB:D7:80:6E:D3:B1:18:CF"),

    // CN=QuoVadis Root CA 2,O=QuoVadis Limited,C=BM
    Quo_Vadis_EV_OID("1.3.6.1.4.1.8024.0.2.100.1.2", "85:A0:DD:7D:D7:20:AD:B7:FF:05:F8:3D:54:2B:20:9D:C7:FF:45:28:F7:D6:77:B1:83:89:FE:A5:E5:C4:9E:86"),

    // CN=Network Solutions Certificate Authority,O=Network Solutions L.L.C.,C=US
    Network_Solutions_EV_OID("1.3.6.1.4.1.782.1.2.1.8.1", "15:F0:BA:00:A3:AC:7A:F3:AC:88:4C:07:2B:10:11:A0:77:BD:77:C0:97:F4:01:64:B2:F8:59:8A:BD:83:86:0C"),

    // CN=Entrust Root Certification Authority,OU="(c) 2006 Entrust, Inc.",OU=www.entrust.net/CPS is incorporated by reference,O="Entrust, Inc.",C=US
    Entrust_EV_OID("2.16.840.1.114028.10.1.2", "73:C1:76:43:4F:1B:C6:D5:AD:F4:5B:0E:76:E7:27:28:7C:8D:E5:76:16:C1:E6:E6:14:1A:2B:2C:BC:7D:8E:4C"),

    // CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
    GlobalSign_EV_OID("1.3.6.1.4.1.4146.1.1", "EB:D4:10:40:E4:BB:3E:C7:42:C9:E3:81:D3:1E:F2:A4:1A:48:B6:68:5C:96:E7:CE:F3:C1:DF:6C:D4:33:1C:99"),

    // CN=GlobalSign,O=GlobalSign,OU=GlobalSign Root CA - R2
    GlobalSign_EV_OID_2("1.3.6.1.4.1.4146.1.1", "CA:42:DD:41:74:5F:D0:B8:1E:B9:02:36:2C:F9:D8:BF:71:9D:A1:BD:1B:1E:FC:94:6F:5B:4C:99:F4:2C:1B:9E"),

    // CN=GlobalSign,O=GlobalSign,OU=GlobalSign Root CA - R3
    GlobalSign_EV_OID_3("1.3.6.1.4.1.4146.1.1", "CB:B5:22:D7:B7:F1:27:AD:6A:01:13:86:5B:DF:1C:D4:10:2E:7D:07:59:AF:63:5A:7C:F4:72:0D:C9:63:C5:3B"),

    // CN=Buypass Class 3 Root CA,O=Buypass AS-983163327,C=NO
    Buypass_EV_OID("2.16.578.1.26.1.3.3", "ED:F7:EB:BC:A2:7A:2A:38:4D:38:7B:7D:40:10:C6:66:E2:ED:B4:84:3E:4C:29:B4:AE:1D:5B:93:32:E6:B2:4D"),

    // CN=Class 2 Primary CA,O=Certplus,C=FR
    Certplus_EV_OID("1.3.6.1.4.1.22234.2.5.2.3.1", "0F:99:3C:8A:EF:97:BA:AF:56:87:14:0E:D5:9A:D1:82:1B:B4:AF:AC:F0:AA:9A:58:B5:D5:7A:33:8A:3A:FB:CB"),

    // CN=Chambers of Commerce Root - 2008,O=AC Camerfirma S.A.,serialNumber=A82743287,L=Madrid (see current address at www.camerfirma.com/address),C=EU
    Camerfirma_EV_OID_a("1.3.6.1.4.1.17326.10.14.2.1.2", "06:3E:4A:FA:C4:91:DF:D3:32:F3:08:9B:85:42:E9:46:17:D8:93:D7:FE:94:4E:10:A7:93:7E:E2:9D:96:93:C0"),

    // CN=Global Chambersign Root - 2008,O=AC Camerfirma S.A.,serialNumber=A82743287,L=Madrid (see current address at www.camerfirma.com/address),C=EU
    Camerfirma_EV_OID_b("1.3.6.1.4.1.17326.10.8.12.1.2", "13:63:35:43:93:34:A7:69:80:16:A0:D3:24:DE:72:28:4E:07:9D:7B:52:20:BB:8F:BD:74:78:16:EE:BE:BA:CA"),

    // CN=AffirmTrust Commercial,O=AffirmTrust,C=US
    AffirmTrust_EV_OID_a("1.3.6.1.4.1.34697.2.1", "03:76:AB:1D:54:C5:F9:80:3C:E4:B2:E2:01:A0:EE:7E:EF:7B:57:B6:36:E8:A9:3C:9B:8D:48:60:C9:6F:5F:A7"),

    // CN=AffirmTrust Networking,O=AffirmTrust,C=US
    AffirmTrust_EV_OID_b("1.3.6.1.4.1.34697.2.2", "0A:81:EC:5A:92:97:77:F1:45:90:4A:F3:8D:5D:50:9F:66:B5:E2:C5:8F:CD:B5:31:05:8B:0E:17:F3:F0:B4:1B"),

    // CN=AffirmTrust Premium,O=AffirmTrust,C=US
    AffirmTrust_EV_OID_c("1.3.6.1.4.1.34697.2.3", "70:A7:3F:7F:37:6B:60:07:42:48:90:45:34:B1:14:82:D5:BF:0E:69:8E:CC:49:8D:F5:25:77:EB:F2:E9:3B:9A"),

    // CN=AffirmTrust Premium ECC,O=AffirmTrust,C=US
    AffirmTrust_EV_OID_d("1.3.6.1.4.1.34697.2.4", "BD:71:FD:F6:DA:97:E4:CF:62:D1:64:7A:DD:25:81:B0:7D:79:AD:F8:39:7E:B4:EC:BA:9C:5E:84:88:82:14:23"),

    // CN=Certum Trusted Network CA,OU=Certum Certification Authority,O=Unizeto Technologies S.A.,C=PL
    Certum_EV_OID("1.2.616.1.113527.2.5.1.1", "5C:58:46:8D:55:F5:8E:49:7E:74:39:82:D2:B5:00:10:B6:D1:65:37:4A:CF:83:A7:D4:A3:2D:B7:68:C4:40:8E"),

    // CN=Izenpe.com,O=IZENPE S.A.,C=ES
    Izenpe_EV_OID_1("1.3.6.1.4.1.14777.6.1.1", "25:30:CC:8E:98:32:15:02:BA:D9:6F:9B:1F:BA:1B:09:9E:2D:29:9E:0F:45:48:BB:91:4F:36:3B:C0:D4:53:1F"),

    // CN=Izenpe.com,O=IZENPE S.A.,C=ES
    Izenpe_EV_OID_2("1.3.6.1.4.1.14777.6.1.2", "25:30:CC:8E:98:32:15:02:BA:D9:6F:9B:1F:BA:1B:09:9E:2D:29:9E:0F:45:48:BB:91:4F:36:3B:C0:D4:53:1F"),

    // CN=T-TeleSec GlobalRoot Class 3,OU=T-Systems Trust Center,O=T-Systems Enterprise Services GmbH,C=DE
    T_Systems_EV_OID("1.3.6.1.4.1.7879.13.24.1", "FD:73:DA:D3:1C:64:4F:F1:B4:3B:EF:0C:CD:DA:96:71:0B:9C:D9:87:5E:CA:7E:31:70:7A:F3:E9:6D:52:2B:BD"),

    // CN=China Internet Network Information Center EV Certificates Root,O=China Internet Network Information Center,C=CN
    CNNIC_EV_OID("1.3.6.1.4.1.29836.1.10", "1C:01:C6:F4:DB:B2:FE:FC:22:55:8B:2B:CA:32:56:3F:49:84:4A:CF:C3:2B:7B:E4:B0:FF:59:9F:9E:8C:7A:F7"),

    // CN=TWCA Root Certification Authority,OU=Root CA,O=TAIWAN-CA,C=TW
    TWCA_EV_OID("1.3.6.1.4.1.40869.1.1.22.3", "BF:D8:8F:E1:10:1C:41:AE:3E:80:1B:F8:BE:56:35:0E:E9:BA:D1:A6:B9:BD:51:5E:DC:5C:6D:5B:87:11:AC:44"),

    // CN=D-TRUST Root Class 3 CA 2 EV 2009,O=D-Trust GmbH,C=DE
    D_TRUST_EV_OID("1.3.6.1.4.1.4788.2.202.1", "EE:C5:49:6B:98:8C:E9:86:25:B9:34:09:2E:EC:29:08:BE:D0:B0:F3:16:C2:D4:73:0C:84:EA:F1:F3:D3:48:81"),

    // CN=Swisscom Root EV CA 2,OU=Digital Certificate Services,O=Swisscom,C=ch
    Swisscom_EV_OID("2.16.756.1.83.21.0", "D9:5F:EA:3C:A4:EE:DC:E7:4C:D7:6E:75:FC:6D:1F:F6:2C:44:1F:0F:A8:BC:77:F0:34:B1:9E:5D:B2:58:01:5D"),

    // CN=VeriSign Universal Root Certification Authority,OU="(c) 2008 VeriSign, Inc. - For authorized use only",OU=VeriSign Trust Network,O="VeriSign, Inc.",C=US
    VeriSign_EV_OID_2("2.16.840.1.113733.1.7.23.6", "23:99:56:11:27:A5:71:25:DE:8C:EF:EA:61:0D:DF:2F:A0:78:B5:C8:06:7F:4E:82:82:90:BF:B8:60:E8:4B:3C"),

    // CN=GeoTrust Primary Certification Authority - G3,OU=(c) 2008 GeoTrust Inc. - For authorized use only,O=GeoTrust Inc.,C=US
    GeoTrust_EV_OID_2("1.3.6.1.4.1.14370.1.6", "B4:78:B8:12:25:0D:F8:78:63:5C:2A:A7:EC:7D:15:5E:AA:62:5E:E8:29:16:E2:CD:29:43:61:88:6C:D1:FB:D4"),

    // CN=thawte Primary Root CA - G3,OU="(c) 2008 thawte, Inc. - For authorized use only",OU=Certification Services Division,O="thawte, Inc.",C=US
    Thawte_EV_OID_2("2.16.840.1.113733.1.7.48.1", "4B:03:F4:58:07:AD:70:F2:1B:FC:2C:AE:71:C9:FD:E4:60:4C:06:4C:F5:FF:B6:86:BA:E5:DB:AA:D7:FD:D3:4C"),

    // CN = Autoridad de Certificacion Firmaprofesional CIF A62634068, C = ES
    Firmaprofesional_EV_OID("1.3.6.1.4.1.13177.10.1.3.10", "04:04:80:28:BF:1F:28:64:D4:8F:9A:D4:D8:32:94:36:6A:82:88:56:55:3F:3B:14:30:3F:90:14:7F:5D:40:EF"),

    // CN = TWCA Global Root CA, OU = Root CA, O = TAIWAN-CA, C = TW
    TWCA_EV_OID_2("1.3.6.1.4.1.40869.1.1.22.3", "59:76:90:07:F7:68:5D:0F:CD:50:87:2F:9F:95:D5:75:5A:5B:2B:45:7D:81:F3:69:2B:61:0A:98:67:2F:0E:1B"),

    // CN = E-Tugra Certification Authority, OU = E-Tugra Sertifikasyon Merkezi, O = E-Tuğra EBG Bilişim Teknolojileri ve Hizmetleri A.Ş., L = Ankara, C = TR
    ETugra_EV_OID("2.16.792.3.0.4.1.1.4", "B0:BF:D5:2B:B0:D7:D9:BD:92:BF:5D:4D:C1:3D:A2:55:C0:2C:54:2F:37:83:65:EA:89:39:11:F5:5E:55:F2:3C"),

    // CN=Actalis Authentication Root CA,O=Actalis S.p.A./03358520967,L=Milan,C=IT
    Actalis_EV_OID("1.3.159.1.17.1", "55:92:60:84:EC:96:3A:64:B9:6E:2A:BE:01:CE:0B:A8:6A:64:FB:FE:BC:C7:AA:B5:AF:C1:55:B3:7F:D7:60:66"),

    // CN=Certification Authority of WoSign,O=WoSign CA Limited,C=CN
    WoSign_EV_OID("1.3.6.1.4.1.36305.2", "4B:22:D5:A6:AE:C9:9F:3C:DB:79:AA:5E:C0:68:38:47:9C:D5:EC:BA:71:64:F7:F2:2D:C1:D6:5F:63:D8:57:08"),

    // CN=CA ...............,O=WoSign CA Limited,C=CN
    WoSign_EV_OID_2("1.3.6.1.4.1.36305.2", "D6:F0:34:BD:94:AA:23:3F:02:97:EC:A4:24:5B:28:39:73:E4:47:AA:59:0F:31:0C:77:F4:8F:DF:83:11:22:54"),

    // CN=DigiCert Assured ID Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US
    DigiCert_EV_OID_2("2.16.840.1.114412.2.1", "7D:05:EB:B6:82:33:9F:8C:94:51:EE:09:4E:EB:FE:FA:79:53:A1:14:ED:B2:F4:49:49:45:2F:AB:7D:2F:C1:85"),

    // CN=DigiCert Assured ID Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US
    DigiCert_EV_OID_3("2.16.840.1.114412.2.1", "7E:37:CB:8B:4C:47:09:0C:AB:36:55:1B:A6:F4:5D:B8:40:68:0F:BA:16:6A:95:2D:B1:00:71:7F:43:05:3F:C2"),

    // CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US
    DigiCert_EV_OID_4("2.16.840.1.114412.2.1",  "CB:3C:CB:B7:60:31:E5:E0:13:8F:8D:D3:9A:23:F9:DE:47:FF:C3:5E:43:C1:14:4C:EA:27:D4:6A:5A:B1:CB:5F"),

    // CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US
    DigiCert_EV_OID_5("2.16.840.1.114412.2.1", "31:AD:66:48:F8:10:41:38:C7:38:F3:9E:A4:32:01:33:39:3E:3A:18:CC:02:29:6E:F9:7C:2A:C9:EF:67:31:D0"),

    // CN=DigiCert Trusted Root G4,OU=www.digicert.com,O=DigiCert Inc,C=US
    DigiCert_EV_OID_6("2.16.840.1.114412.2.1", "55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88"),

    // CN=QuoVadis Root CA 2 G3,O=QuoVadis Limited,C=BM
    QuoVadis_EV_OID("1.3.6.1.4.1.8024.0.2.100.1.2", "8F:E4:FB:0A:F9:3A:4D:0D:67:DB:0B:EB:B2:3E:37:C7:1B:F3:25:DC:BC:DD:24:0E:A0:4D:AF:58:B4:7E:18:40"),

    // CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
    Comodo_EV_OID_5("1.3.6.1.4.1.6449.1.2.1.5.1", "52:F0:E1:C4:E5:8E:C6:29:29:1B:60:31:7F:07:46:71:B8:5D:7E:A8:0D:5B:07:27:34:63:53:4B:32:B4:02:34"),

    // CN=USERTrust RSA Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US
    Comodo_EV_OID_6("1.3.6.1.4.1.6449.1.2.1.5.1", "E7:93:C9:B0:2F:D8:AA:13:E2:1C:31:22:8A:CC:B0:81:19:64:3B:74:9C:89:89:64:B1:74:6D:46:C3:D4:CB:D2"),

    // CN=USERTrust ECC Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US
    Comodo_EV_OID_7("1.3.6.1.4.1.6449.1.2.1.5.1", "4F:F4:60:D5:4B:9C:86:DA:BF:BC:FC:57:12:E0:40:0D:2B:ED:3F:BC:4D:4F:BD:AA:86:E0:6A:DC:D2:A9:AD:7A"),

    // CN=GlobalSign,O=GlobalSign,OU=GlobalSign ECC Root CA - R4
    GlobalSign_EV_OID_4("1.3.6.1.4.1.4146.1.1", "BE:C9:49:11:C2:95:56:76:DB:6C:0A:55:09:86:D7:6E:3B:A0:05:66:7C:44:2C:97:62:B4:FB:B7:73:DE:22:8C"),

    // CN=GlobalSign,O=GlobalSign,OU=GlobalSign ECC Root CA - R5
    GlobalSign_EV_OID_5("1.3.6.1.4.1.4146.1.1", "17:9F:BC:14:8A:3D:D0:0F:D2:4E:A1:34:58:CC:43:BF:A7:F5:9C:81:82:D7:83:A5:13:F6:EB:EC:10:0C:89:24"),

    // CN=Entrust.net Certification Authority (2048),OU=(c) 1999 Entrust.net Limited,OU=www.entrust.net/CPS_2048 incorp. by ref. (limits liab.),O=Entrust.net
    Entrust_EV_OID_2("2.16.840.1.114028.10.1.2", "6D:C4:71:72:E0:1C:BC:B0:BF:62:58:0D:89:5F:E2:B8:AC:9A:D4:F8:73:80:1E:0C:10:B9:C8:37:D2:1E:B1:77"),

    // CN=Staat der Nederlanden EV Root CA,O=Staat der Nederlanden,C=NL
    Staat_der_Nederlanden_EV_OID("2.16.528.1.1003.1.2.7", "4D:24:91:41:4C:FE:95:67:46:EC:4C:EF:A6:CF:6F:72:E2:8A:13:29:43:2F:9D:8A:90:7A:C4:CB:5D:AD:C1:5A"),

    // CN=Entrust Root Certification Authority - G2,OU="(c) 2009 Entrust, Inc. - for authorized use only",OU=See www.entrust.net/legal-terms,O="Entrust, Inc.",C=US
    Entrust_EV_OID_3("2.16.840.1.114028.10.1.2", "43:DF:57:74:B0:3E:7F:EF:5F:E4:0D:93:1A:7B:ED:F1:BB:2E:6B:42:73:8C:4E:6D:38:41:10:3D:3A:A7:F3:39"),

    // CN=Entrust Root Certification Authority - EC1,OU="(c) 2012 Entrust, Inc. - for authorized use only",OU=See www.entrust.net/legal-terms,O="Entrust, Inc.",C=US
    Entrust_EV_OID_4("2.16.840.1.114028.10.1.2", "02:ED:0E:B2:8C:14:DA:45:16:5C:56:67:91:70:0D:64:51:D7:FB:56:F0:B2:AB:1D:3B:8E:B0:70:E5:6E:DF:F5"),

    // CN=CFCA EV ROOT,O=China Financial Certification Authority,C=CN
    CFCA_EV_OID("2.16.156.112554.3", "5C:C3:D7:8E:4E:1D:5E:45:54:7A:04:E6:87:3E:64:F9:0C:F9:53:6D:1C:CC:2E:F8:00:F3:55:C4:C5:FD:70:FD"),

    // CN=Certification Authority of WoSign G2,O=WoSign CA Limited,C=CN
    WoSign_EV_OID_3("1.3.6.1.4.1.36305.2", "D4:87:A5:6F:83:B0:74:82:E8:5E:96:33:94:C1:EC:C2:C9:E5:1D:09:03:EE:94:6B:02:C3:01:58:1E:D9:9E:16"),

    // CN=CA WoSign ECC Root,O=WoSign CA Limited,C=CN
    WoSign_EV_OID_4("1.3.6.1.4.1.36305.2", "8B:45:DA:1C:06:F7:91:EB:0C:AB:F2:6B:E5:88:F5:FB:23:16:5C:2E:61:4B:F8:85:56:2D:0D:CE:50:B2:9B:02"),

    // CN=TÜRKTRUST Elektronik Sertifika Hizmet Sağlayıcısı H6,O=TÜRKTRUST Bilgi İletişim ve Bilişim Güvenliği Hizmetleri A...,L=Ankara,C=TR
    TurkTrust_EV_OID("2.16.792.3.0.3.1.1.5", "8D:E7:86:55:E1:BE:7F:78:47:80:0B:93:F6:94:D2:1D:36:8C:C0:6E:03:3E:7F:AB:04:BB:5E:B9:9D:A6:B7:00"),

    // OU=Security Communication RootCA2,O="SECOM Trust Systems CO.,LTD.",C=JP
    SECOM_EV_OID_2("1.2.392.200091.100.721.1", "51:3B:2C:EC:B8:10:D4:CD:E5:DD:85:39:1A:DF:C6:C2:DD:60:D8:7B:B7:36:D2:B5:21:48:4A:A4:7A:0E:BE:F6"),

    // CN=OISTE WISeKey Global Root GB CA,OU=OISTE Foundation Endorsed,O=WISeKey,C=CH
    WISeKey_EV_OID("2.16.756.5.14.7.4.8", "6B:9C:08:E8:6E:B0:F7:67:CF:AD:65:CD:98:B6:21:49:E5:49:4A:67:F5:84:5E:7B:D1:ED:01:9F:27:B8:6B:D6");
	
    private String oid;
    private String rootCertSHA256;
    
    private ExtendedValidationOID(String oid, String rootCertSHA256) {
    	this.oid = oid;
    	this.rootCertSHA256 = rootCertSHA256;
    }
    
    public String getOID() {
    	return oid;
    }
    
    public String getRootCertSHA256() {
    	return rootCertSHA256;
    }

    private static final Map<String,ExtendedValidationOID> lookup = new HashMap<String,ExtendedValidationOID>();

    static {
    	for (ExtendedValidationOID oid : EnumSet.allOf(ExtendedValidationOID.class)) {
    		lookup.put(oid.getRootCertSHA256(), oid);
    	}
    }
    
    public static ExtendedValidationOID oidByRootCertSHA256(String rootCertSHA256) {
    	return lookup.get(rootCertSHA256);
    }
}
