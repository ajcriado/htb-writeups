###  Nmap

```bash
# Nmap 7.94SVN scan initiated Wed Dec 13 08:43:02 2023 as: nmap -p 21,80,111,135,139,445,2049,5985,47001,49664,49665,49666,49667,49678,49679,49680 -sCV -A -T4 -O -oN full-scan.nmap 10.129.229.68
Nmap scan report for 10.129.229.68
Host is up (0.037s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  nlockmgr      1-4 (RPC #100021)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows 2019|2012|2022|10|Vista|2016|7|2008|Longhorn (95%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_10:1511 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows
Aggressive OS guesses: Microsoft Windows Server 2019 (95%), Microsoft Windows Server 2012 R2 (92%), Microsoft Windows Server 2022 (92%), Microsoft Windows 10 1909 (92%), Microsoft Windows Server 2012 (87%), Microsoft Windows Vista SP1 (87%), Microsoft Windows 10 1709 - 1909 (87%), Microsoft Windows Server 2012 or Server 2012 R2 (87%), Microsoft Windows Server 2016 (87%), Microsoft Windows 10 1703 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-12-13T07:44:06
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   37.21 ms 10.10.14.1
2   37.41 ms 10.129.229.68

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 13 08:44:26 2023 -- 1 IP address (1 host up) scanned in 83.99 seconds
```

### NFS

```bash
# Nmap 7.94SVN scan initiated Wed Dec 13 08:51:54 2023 as: nmap --script nfs* -sV -p111,2049 -oN nfs-scan 10.129.229.68
Nmap scan report for 10.129.229.68
Host is up (0.037s latency).

PORT     STATE SERVICE  VERSION
111/tcp  open  rpcbind?
| rpcinfo: 
|   program version    port/proto  service
|   100021  4           2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
2049/tcp open  status   1 (RPC #100024)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 13 08:53:07 2023 -- 1 IP address (1 host up) scanned in 72.80 seconds
```
```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Remote]
└─$ showmount -e 10.129.229.68    
Export list for 10.129.229.68:
/site_backups (everyone)
```

### Fuzzing

```bash
# Dirsearch started Wed Dec 13 09:41:29 2023 as: /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u http://10.129.229.68/ -o dirsearch

403   312B   http://10.129.229.68/%2e%2e//google.com
403   312B   http://10.129.229.68/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
404     2KB  http://10.129.229.68/.ashx
404     2KB  http://10.129.229.68/.asmx
403   312B   http://10.129.229.68/\..\..\..\..\..\..\..\..\..\etc\passwd
200     2KB  http://10.129.229.68/about-us
404     2KB  http://10.129.229.68/admin%20/
404     2KB  http://10.129.229.68/admin.
404     2KB  http://10.129.229.68/asset..
400    11B   http://10.129.229.68/base/
500     1KB  http://10.129.229.68/base/static/c
403   312B   http://10.129.229.68/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
200     2KB  http://10.129.229.68/blog/
200     2KB  http://10.129.229.68/blog
200     3KB  http://10.129.229.68/contact.aspx
200     3KB  http://10.129.229.68/contact
400     3KB  http://10.129.229.68/docpicker/internal_proxy/https/127.0.0.1:9043/ibm/console
200     2KB  http://10.129.229.68/home
200     2KB  http://10.129.229.68/home.aspx
400     3KB  http://10.129.229.68/index.php::$DATA
404     2KB  http://10.129.229.68/index.php.
302   126B   http://10.129.229.68/install    -> REDIRECTS TO: /umbraco/
302   126B   http://10.129.229.68/Install    -> REDIRECTS TO: /umbraco/
302   126B   http://10.129.229.68/INSTALL    -> REDIRECTS TO: /umbraco/
302   126B   http://10.129.229.68/install/    -> REDIRECTS TO: /umbraco/
200     1KB  http://10.129.229.68/intranet
404     2KB  http://10.129.229.68/javax.faces.resource.../WEB-INF/web.xml.jsf
404     2KB  http://10.129.229.68/javax.faces.resource.../
400     3KB  http://10.129.229.68/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
400     3KB  http://10.129.229.68/jolokia/exec/com.sun.management:type=DiagnosticCommand/help/*
400     3KB  http://10.129.229.68/jolokia/exec/com.sun.management:type=DiagnosticCommand/vmLog/output=!/tmp!/pwned
400     3KB  http://10.129.229.68/jolokia/exec/com.sun.management:type=DiagnosticCommand/jvmtiAgentLoad/!/etc!/passwd
400     3KB  http://10.129.229.68/jolokia/exec/com.sun.management:type=DiagnosticCommand/vmLog/disable
400     3KB  http://10.129.229.68/jolokia/exec/java.lang:type=Memory/gc
400     3KB  http://10.129.229.68/jolokia/exec/com.sun.management:type=DiagnosticCommand/jfrStart/filename=!/tmp!/foo
400     3KB  http://10.129.229.68/jolokia/read/java.lang:type=*/HeapMemoryUsage
400     3KB  http://10.129.229.68/jolokia/exec/com.sun.management:type=DiagnosticCommand/vmSystemProperties
400     3KB  http://10.129.229.68/jolokia/read/java.lang:type=Memory/HeapMemoryUsage/used
400     3KB  http://10.129.229.68/jolokia/search/*:j2eeType=J2EEServer,*
400     3KB  http://10.129.229.68/jolokia/write/java.lang:type=Memory/Verbose/true
404     2KB  http://10.129.229.68/login.wdm%20
404     2KB  http://10.129.229.68/login.wdm%2e
500     3KB  http://10.129.229.68/master/
200     2KB  http://10.129.229.68/people
200     2KB  http://10.129.229.68/products.aspx
200     2KB  http://10.129.229.68/products
404     2KB  http://10.129.229.68/rating_over.
500     3KB  http://10.129.229.68/product.aspx
500     3KB  http://10.129.229.68/product
404     2KB  http://10.129.229.68/service.asmx
404     2KB  http://10.129.229.68/static..
403     2KB  http://10.129.229.68/Trace.axd
400     3KB  http://10.129.229.68/Trace.axd::$DATA
404     2KB  http://10.129.229.68/WEB-INF./
404     2KB  http://10.129.229.68/WEB-INF./web.xml
200     6KB  http://10.129.229.68/umbraco/webservices/codeEditorSave.asmx
400     3KB  http://10.129.229.68/web.config::$DATA
404     2KB  http://10.129.229.68/WebResource.axd?d=LER8t9aS
```