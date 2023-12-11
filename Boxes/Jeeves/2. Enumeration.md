### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Jeeves-10.10.10.63/nmap]
└─$ nmap -p80,135,445 -sC -sV -A -T4 10.10.10.63          
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-15 10:03 CEST
Nmap scan report for 10.10.10.63
Host is up (0.24s latency).

PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Ask Jeeves
135/tcp open  msrpc        Microsoft Windows RPC
445/tcp open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http    Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 5h00m00s, deviation: 0s, median: 4h59m59s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-08-15T13:03:12
|_  start_date: 2023-08-15T12:59:59

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.69 seconds
```


### Gobuster

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.63:50000/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.63:50000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/08/15 10:27:41 Starting gobuster in directory enumeration mode
===============================================================
/askjeeves            (Status: 302) [Size: 0] [--> http://10.10.10.63:50000/askjeeves/]
Progress: 87604 / 87665 (99.93%)
===============================================================
2023/08/15 10:37:57 Finished
===============================================================


┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.63:80/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.63:80/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/08/15 10:27:19 Starting gobuster in directory enumeration mode
===============================================================
Progress: 87637 / 87665 (99.97%)
===============================================================
2023/08/15 10:38:02 Finished
===============================================================
```