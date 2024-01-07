
### Nmap

```bash
# Nmap 7.94SVN scan initiated Sun Jan  7 09:07:50 2024 as: nmap -p 22,80,443 -sCV -A -T4 -O -oN nmap/port-scan 10.129.24.125
Nmap scan report for bizness.htb (10.129.24.125)
Host is up (0.047s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp open  ssl/http nginx 1.18.0
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
|_http-title: 400 The plain HTTP request was sent to HTTPS port
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
|_http-server-header: nginx/1.18.0
| tls-alpn: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 (99%), Linux 4.15 - 5.8 (95%), Linux 5.0 - 5.4 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), HP P2000 G3 NAS device (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   52.65 ms 10.10.14.1
2   52.73 ms bizness.htb (10.129.24.125)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan  7 09:08:12 2024 -- 1 IP address (1 host up) scanned in 22.22 seconds
```

### Fuzzing

#### Dirsearch

```bash
# Dirsearch started Sun Jan  7 09:20:48 2024 as: /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u https://bizness.htb/

400   795B   https://bizness.htb/\..\..\..\..\..\..\..\..\..\etc\passwd
400   795B   https://bizness.htb/a%5c.aspx
302     0B   https://bizness.htb/accounting    -> REDIRECTS TO: https://bizness.htb/accounting/
302     0B   https://bizness.htb/catalog    -> REDIRECTS TO: https://bizness.htb/catalog/
302     0B   https://bizness.htb/common    -> REDIRECTS TO: https://bizness.htb/common/
302     0B   https://bizness.htb/content/    -> REDIRECTS TO: https://bizness.htb/content/control/main
302     0B   https://bizness.htb/content/debug.log    -> REDIRECTS TO: https://bizness.htb/content/control/main
302     0B   https://bizness.htb/content    -> REDIRECTS TO: https://bizness.htb/content/
200    34KB  https://bizness.htb/control
200    34KB  https://bizness.htb/control/
302     0B   https://bizness.htb/error    -> REDIRECTS TO: https://bizness.htb/error/
302     0B   https://bizness.htb/example    -> REDIRECTS TO: https://bizness.htb/example/
200    11KB  https://bizness.htb/control/login
302     0B   https://bizness.htb/images    -> REDIRECTS TO: https://bizness.htb/images/
302     0B   https://bizness.htb/index.jsp    -> REDIRECTS TO: https://bizness.htb/control/main
302     0B   https://bizness.htb/solr/    -> REDIRECTS TO: https://bizness.htb/solr/control/checkLogin/
200    21B   https://bizness.htb/solr/admin/file/?file=solrconfig.xml
200    21B   https://bizness.htb/solr/admin/
```

### Script to crack hash for OFBiz

```java
import org.apache.commons.codec.binary.Base64;

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;
import java.io.FileReader;

public class decrypthash {
public static void main(String[] args) {

String filePath = "/home/acriado/Documentos/Shared/rockyou.txt";
  
try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
String line;  

while ((line = reader.readLine()) != null) {
byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
String hash = cryptBytes("SHA", "d", bytes);
System.out.println(hash);
if (hash.equals("$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I")){
System.out.println("[+] Password: " + line);
break;
}
}
} catch (IOException ignored) {}
}
  
public static String cryptBytes(String hashType, String salt, byte[] bytes) {
StringBuilder sb = new StringBuilder();
sb.append("$").append(hashType).append("$").append(salt).append("$");
sb.append(getCryptedBytes(hashType, salt, bytes));
return sb.toString();
}

private static String getCryptedBytes(String hashType, String salt, byte[] bytes) {
try {
MessageDigest messagedigest = MessageDigest.getInstance("SHA");
messagedigest.update("d".getBytes(StandardCharsets.UTF_8));
messagedigest.update(bytes);
return Base64.encodeBase64URLSafeString(messagedigest.digest()).replace('+', '.');
} catch (NoSuchAlgorithmException e) {
throw new RuntimeException("Error while comparing password", e);
}
}
}
```