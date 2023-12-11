### Nmap

```bash
┌─[htb-student@par01]─[~]
└──╼ $nmap -A -T4 172.16.5.0/24
nmap -A -T4 172.16.5.0/24
Starting Nmap 7.92 ( https://nmap.org ) at 2023-11-27 16:32 EST
Nmap scan report for inlanefreight.local (172.16.5.5)
Host is up (0.018s latency).
Not shown: 988 closed tcp ports (conn-refused)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-11-27 21:32:58Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.INLANEFREIGHT.LOCAL
| Not valid before: 2023-11-26T19:12:24
|_Not valid after:  2024-05-27T19:12:24
|_ssl-date: 2023-11-27T21:36:30+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: INLANEFREIGHT
|   NetBIOS_Domain_Name: INLANEFREIGHT
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: INLANEFREIGHT.LOCAL
|   DNS_Computer_Name: DC01.INLANEFREIGHT.LOCAL
|   DNS_Tree_Name: INLANEFREIGHT.LOCAL
|   Product_Version: 10.0.17763
|_  System_Time: 2023-11-27T21:35:31+00:00
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:74:89 (VMware)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-11-27T21:35:29
|_  start_date: N/A

Nmap scan report for 172.16.5.127
Host is up (0.065s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Inlane Freight
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 172.16.5.130
Host is up (0.068s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-11-27T21:36:30+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=FILE01.INLANEFREIGHT.LOCAL
| Not valid before: 2023-11-26T19:12:27
|_Not valid after:  2024-05-27T19:12:27
| rdp-ntlm-info: 
|   Target_Name: INLANEFREIGHT
|   NetBIOS_Domain_Name: INLANEFREIGHT
|   NetBIOS_Computer_Name: FILE01
|   DNS_Domain_Name: INLANEFREIGHT.LOCAL
|   DNS_Computer_Name: FILE01.INLANEFREIGHT.LOCAL
|   DNS_Tree_Name: INLANEFREIGHT.LOCAL
|   Product_Version: 10.0.17763
|_  System_Time: 2023-11-27T21:35:30+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-11-27T21:35:29
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: FILE01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:41:11 (VMware)

Nmap scan report for 172.16.5.200
Host is up (0.063s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
80/tcp   open  http?
| http-webdav-scan: 
|   Server Type: Microsoft-HTTPAPI/2.0
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, LOCK, UNLOCK
|   Server Date: Mon, 27 Nov 2023 15:35:44 GMT
|_  Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
| http-ntlm-info: 
|   Target_Name: DEV01
|   NetBIOS_Domain_Name: NT AUTHORITY
|   NetBIOS_Computer_Name: DEV01
|   DNS_Domain_Name: INLANEFREIGHT.LOCAL
|   DNS_Computer_Name: DEV01
|   DNS_Tree_Name: INLANEFREIGHT.LOCAL
|_  Product_Version: 10.0.19041
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  NTLM
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND LOCK UNLOCK PROPPATCH MKCOL PUT DELETE MOVE
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap?
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: INLANEFREIGHT
|   NetBIOS_Domain_Name: INLANEFREIGHT
|   NetBIOS_Computer_Name: DEV01
|   DNS_Domain_Name: INLANEFREIGHT.LOCAL
|   DNS_Computer_Name: DEV01.INLANEFREIGHT.LOCAL
|   DNS_Tree_Name: INLANEFREIGHT.LOCAL
|   Product_Version: 10.0.17763
|_  System_Time: 2023-11-27T21:35:29+00:00
| ssl-cert: Subject: commonName=DEV01.INLANEFREIGHT.LOCAL
| Not valid before: 2023-11-26T19:12:21
|_Not valid after:  2024-05-27T19:12:21
|_ssl-date: 2023-11-27T21:36:30+00:00; 0s from scanner time.
8080/tcp open  http          Apache Tomcat 10.0.21
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat/10.0.21
|_http-favicon: Apache Tomcat
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-11-27T21:35:35
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: DEV01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:b1:2a (VMware)

Nmap scan report for 172.16.5.225
Host is up (0.068s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 97:cc:9f:d0:a3:84:da:d1:a2:01:58:a1:f2:71:37:e5 (RSA)
|   256 03:15:a9:1c:84:26:87:b7:5f:8d:72:73:9f:96:e0:f2 (ECDSA)
|_  256 55:c9:4a:d2:63:8b:5f:f2:ed:7b:4e:38:e1:c9:f5:71 (ED25519)
80/tcp   open  http          nginx 1.21.6
|_http-title: Did not follow redirect to https://172.16.5.225/
|_http-server-header: nginx/1.21.6
443/tcp  open  ssl/http      nginx 1.21.6
|_http-server-header: nginx/1.21.6
| ssl-cert: Subject: commonName=writehat.corp.local/organizationName=Black Lantern Security/stateOrProvinceName=SC/countryName=US
| Not valid before: 2020-11-20T14:26:49
|_Not valid after:  2048-04-06T14:26:49
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_ssl-date: TLS randomness does not represent time
| http-title: WH - WriteHat - Log In
|_Requested resource was /login?next=/
1234/tcp open  http          SimpleHTTPServer 0.6 (Python 3.9.2)
3389/tcp open  ms-wbt-server xrdp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (5 hosts up) scanned in 334.17 seconds
```