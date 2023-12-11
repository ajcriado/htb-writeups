## Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Grandpa-10.10.10.14/nmap]
└─$ sudo nmap -p 80 -sVC -A -T4 -O 10.10.10.14 -oA services
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-01 08:13 CEST
Nmap scan report for 10.10.10.14
Host is up (0.047s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|_  Server Date: Tue, 01 Aug 2023 06:14:09 GMT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|2008|XP|2000 (90%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_2000::sp4
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (90%), Microsoft Windows Server 2003 SP2 (89%), Microsoft Windows Server 2008 Enterprise SP2 (88%), Microsoft Windows XP SP3 (88%), Microsoft Windows 2000 SP4 or Windows XP Professional SP1 (88%), Microsoft Windows 2003 SP2 (87%), Microsoft Windows XP (85%), Microsoft Windows XP SP2 (85%), Microsoft Windows Server 2003 SP1 - SP2 (85%), Microsoft Windows XP SP2 or SP3 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   46.21 ms 10.10.14.1
2   46.25 ms 10.10.10.14

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.52 seconds
```