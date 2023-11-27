172.16.5.200
Windows

```bash
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
|_http-title: Site doesnt have a title (text/html).
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
```