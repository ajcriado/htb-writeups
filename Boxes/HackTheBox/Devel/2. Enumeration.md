### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Devel-10.10.10.5]
└─$ sudo nmap -p 21,80 10.10.10.5 -sCV -A -T4 -O -Pn                   
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-31 21:31 CEST
Nmap scan report for 10.10.10.5
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|7|2008|8.1|Vista (91%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (91%), Microsoft Windows Phone 7.5 or 8.0 (91%), Microsoft Windows Embedded Standard 7 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (88%), Microsoft Windows Server 2008 R2 (88%), Microsoft Windows Server 2008 R2 or Windows 8.1 (88%), Microsoft Windows Server 2008 R2 SP1 (88%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (88%), Microsoft Windows 7 (88%), Microsoft Windows 7 Professional or Windows 8 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   85.88 ms 10.10.14.1
2   89.55 ms 10.10.10.5

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.17 seconds
```