### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Hospital-10.10.11.241]
└─$ sudo nmap -p 22,53,88,135,139,389,443,445,464,593,636,1801,2103,2105,2107,2179,3268,3269,3389,5985,6404,6406,6407,6409,6615,6632,8080,9389,22651 -sCV -A -T4 -O -Pn 10.10.11.241
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-19 17:47 CET
Nmap scan report for 10.10.11.241
Host is up (0.052s latency).

PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-11-19 23:48:05Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp   open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp  open  msmq?
2103/tcp  open  msrpc             Microsoft Windows RPC
2105/tcp  open  msrpc             Microsoft Windows RPC
2107/tcp  open  msrpc             Microsoft Windows RPC
2179/tcp  open  vmrdp?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp  open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2023-11-19T23:49:11+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2023-09-05T18:39:34
|_Not valid after:  2024-03-06T18:39:34
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
6404/tcp  open  msrpc             Microsoft Windows RPC
6406/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp  open  msrpc             Microsoft Windows RPC
6409/tcp  open  msrpc             Microsoft Windows RPC
6615/tcp  open  msrpc             Microsoft Windows RPC
6632/tcp  open  msrpc             Microsoft Windows RPC
8080/tcp  open  http              Apache httpd 2.4.55 ((Ubuntu))
|_http-server-header: Apache/2.4.55 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-open-proxy: Proxy might be redirecting requests
| http-title: Login
|_Requested resource was login.php
9389/tcp  open  mc-nmf            .NET Message Framing
22651/tcp open  msrpc             Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 5.X (91%)
OS CPE: cpe:/o:linux:linux_kernel:5.0
Aggressive OS guesses: Linux 5.0 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-time: 
|   date: 2023-11-19T23:49:14
|_  start_date: N/A

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   50.77 ms 10.10.14.1
2   52.04 ms 10.10.11.241

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 128.69 seconds
```

### Enumeration

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://10.10.11.241:8080/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )                                                                                             
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_10.10.11.241_8080/__23-11-19_17-49-13.txt

Target: http://10.10.11.241:8080/

[17:49:13] Starting:                                                                                                
[17:49:16] 301 -  316B  - /js  ->  http://10.10.11.241:8080/js/             
[17:49:18] 403 -  279B  - /.ht_wsr.txt                                      
[17:49:18] 403 -  279B  - /.htaccess.orig                                   
[17:49:18] 403 -  279B  - /.htaccess.sample                                 
[17:49:18] 403 -  279B  - /.htaccess.bak1
[17:49:18] 403 -  279B  - /.htaccess_extra                                  
[17:49:18] 403 -  279B  - /.htaccess.save                                   
[17:49:18] 403 -  279B  - /.htaccess_orig                                   
[17:49:18] 403 -  279B  - /.htaccessOLD2
[17:49:18] 403 -  279B  - /.htaccess_sc
[17:49:18] 403 -  279B  - /.htaccessOLD                                     
[17:49:18] 403 -  279B  - /.htaccessBAK
[17:49:18] 403 -  279B  - /.htm
[17:49:18] 403 -  279B  - /.html
[17:49:18] 403 -  279B  - /.htpasswds                                       
[17:49:18] 403 -  279B  - /.httr-oauth
[17:49:18] 403 -  279B  - /.htpasswd_test                                   
[17:49:19] 403 -  279B  - /.php                                             
[17:49:41] 200 -    0B  - /config.php                                       
[17:49:43] 301 -  317B  - /css  ->  http://10.10.11.241:8080/css/           
[17:49:49] 301 -  319B  - /fonts  ->  http://10.10.11.241:8080/fonts/       
[17:49:52] 301 -  320B  - /images  ->  http://10.10.11.241:8080/images/     
[17:49:52] 403 -  279B  - /images/
[17:49:54] 403 -  279B  - /js/                                              
[17:49:56] 200 -    2KB - /login.php                                        
[17:50:10] 200 -    2KB - /register.php                                     
[17:50:12] 403 -  279B  - /server-status                                    
[17:50:12] 403 -  279B  - /server-status/                                   
[17:50:22] 200 -    0B  - /upload.php                                       
[17:50:22] 403 -  279B  - /uploads/                                         
[17:50:22] 301 -  321B  - /uploads  ->  http://10.10.11.241:8080/uploads/   
[17:50:24] 403 -  279B  - /vendor/                                          
                                                                             
Task Completed
```

```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://hospital.htb:8080/FUZZ.php

        /___\  /___\           /___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hospital.htb:8080/FUZZ.php
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

login                   [Status: 200, Size: 5739, Words: 1551, Lines: 134, Duration: 58ms]
register                [Status: 200, Size: 5125, Words: 1349, Lines: 114, Duration: 53ms]
upload                  [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 51ms]
index                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 4053ms]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 54ms]
success                 [Status: 200, Size: 3536, Words: 134, Lines: 84, Duration: 53ms]
config                  [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 54ms]
                        [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 52ms]
:: Progress: [87650/87650] :: Job [1/1] :: 714 req/sec :: Duration: [0:02:12] :: Errors: 0 ::

┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:8080/ -H 'Host: FUZZ.hospital.htb'   

        /___\  /___\           /___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://academy.htb:8080/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.hospital.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 563 req/sec :: Duration: [0:00:07] :: Errors: 4989 ::
```