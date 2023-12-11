### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/SolidState-10.10.10.51]
└─$ sudo nmap -p 22,25,80,110,119,4555 -sCV -A -T4 -O 10.10.10.51 
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-17 13:17 CET
Stats: 0:04:16 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 89.58% done; ETC: 13:21 (0:00:05 remaining)
Nmap scan report for 10.10.10.51
Host is up (0.051s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.5 [10.10.14.5])
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3    JAMES pop3d 2.3.2
119/tcp  open  nntp    JAMES nntpd (posting ok)
4555/tcp open  rsip?
| fingerprint-strings: 
|   GenericLines: 
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for 
|_    Login id:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4555-TCP:V=7.94SVN%I=7%D=11/17%Time=655759E2%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,7C,"JAMES\x20Remote\x20Administration\x20Tool\x202\.3\.2
SF:\nPlease\x20enter\x20your\x20login\x20and\x20password\nLogin\x20id:\nPa
SF:ssword:\nLogin\x20failed\x20for\x20\nLogin\x20id:\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.4 (95%), Linux 4.2 (95%), Linux 4.8 (95%), Linux 4.9 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   50.10 ms 10.10.14.1
2   50.19 ms 10.10.10.51

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 293.53 seconds
```

### Fuzzing

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://10.10.10.51:80/ 
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )                                                                                             
                                                                                                                    
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_10.10.10.51_80/__23-11-17_13-19-49.txt

Target: http://10.10.10.51/

[13:19:49] Starting:                                                                                                
[13:19:54] 403 -  300B  - /.htaccess.orig                                   
[13:19:54] 403 -  302B  - /.htaccess.sample
[13:19:54] 403 -  300B  - /.htaccess.bak1                                   
[13:19:54] 403 -  297B  - /.ht_wsr.txt                                      
[13:19:54] 403 -  300B  - /.htaccess.save
[13:19:54] 403 -  300B  - /.htaccess_orig                                   
[13:19:54] 403 -  301B  - /.htaccess_extra
[13:19:54] 403 -  298B  - /.htaccessOLD
[13:19:54] 403 -  298B  - /.htaccessBAK
[13:19:54] 403 -  298B  - /.htaccess_sc
[13:19:54] 403 -  299B  - /.htaccessOLD2                                    
[13:19:54] 403 -  296B  - /.htpasswds                                       
[13:19:54] 403 -  297B  - /.httr-oauth                                      
[13:19:54] 403 -  291B  - /.html                                            
[13:19:54] 403 -  290B  - /.htm                                             
[13:19:54] 403 -  300B  - /.htpasswd_test                                   
[13:20:00] 200 -    3KB - /about.html                                       
[13:20:11] 301 -  311B  - /assets  ->  http://10.10.10.51/assets/           
[13:20:11] 200 -  467B  - /assets/                                          
[13:20:27] 200 -  568B  - /images/                                          
[13:20:27] 301 -  311B  - /images  ->  http://10.10.10.51/images/           
[13:20:31] 200 -    6KB - /LICENSE.txt                                      
[13:20:45] 200 -  606B  - /README.txt                                       
[13:20:48] 403 -  299B  - /server-status                                    
[13:20:48] 403 -  300B  - /server-status/                                   
                                                                             
Task Completed
```