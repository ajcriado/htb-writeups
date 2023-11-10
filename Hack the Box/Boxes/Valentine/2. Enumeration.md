### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Valentine-10.10.10.79]
└─$ sudo nmap -p 22,80,443 -sCV -A -T4 -O 10.10.10.79                                                           
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-30 12:51 CET
Nmap scan report for 10.10.10.79
Host is up (0.031s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesnt have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesnt have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2023-10-30T11:52:13+00:00; 0s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Nokia N9 phone (Linux 2.6.32) (96%), Linux 3.2 (96%), Linux 2.6.32 - 3.5 (95%), Linux 3.0 (95%), Linux 2.6.38 - 3.0 (94%), Linux 2.6.38 - 2.6.39 (94%), Linux 2.6.39 (94%), Linux 2.6.32 - 3.10 (93%), Linux 2.6.32 - 3.9 (93%), Android 4.2.2 (Linux 3.4) (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   30.93 ms 10.10.14.1
2   31.13 ms 10.10.10.79

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.14 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p 5353 -sU -sCV -A -T4 10.10.10.79
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-30 13:02 CET
Nmap scan report for valentine.htb (10.10.10.79)
Host is up (0.031s latency).

PORT     STATE SERVICE VERSION
5353/udp open  mdns    DNS-based service discovery
| dns-service-discovery: 
|   9/tcp workstation
|     Address=10.10.10.79 dead:beef::250:56ff:feb9:e9b5
|   22/tcp udisks-ssh
|_    Address=10.10.10.79 dead:beef::250:56ff:feb9:e9b5
Too many fingerprints match this host to give specific OS details
Network Distance: 2 hops

TRACEROUTE (using port 5353/udp)
HOP RTT      ADDRESS
1   30.45 ms 10.10.14.1
2   ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.75 seconds
```

### Fuzzing

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://10.10.10.79:80/

  _|. _ _  _  _  _ _|_    v0.4.2                                                                                    
 (_||| _) (/_(_|| (_| )                                                                                             
                                                                                                                    
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/10.10.10.79-80/-_23-10-30_12-56-05.txt

Error Log: /home/kali/.dirsearch/logs/errors-23-10-30_12-56-05.log

Target: http://10.10.10.79:80/

[12:56:05] Starting: 
[12:56:08] 403 -  290B  - /.ht_wsr.txt                                     
[12:56:08] 403 -  293B  - /.htaccess.bak1                                  
[12:56:08] 403 -  293B  - /.htaccess.orig
[12:56:08] 403 -  295B  - /.htaccess.sample
[12:56:08] 403 -  293B  - /.htaccess.save
[12:56:08] 403 -  291B  - /.htaccessBAK
[12:56:08] 403 -  294B  - /.htaccess_extra
[12:56:08] 403 -  293B  - /.htaccess_orig
[12:56:08] 403 -  292B  - /.htaccessOLD2
[12:56:08] 403 -  291B  - /.htaccessOLD
[12:56:08] 403 -  291B  - /.htaccess_sc                                    
[12:56:08] 403 -  283B  - /.htm
[12:56:08] 403 -  284B  - /.html
[12:56:08] 403 -  293B  - /.htpasswd_test
[12:56:08] 403 -  289B  - /.htpasswds
[12:56:08] 403 -  290B  - /.httr-oauth                                     
[12:56:24] 403 -  287B  - /cgi-bin/                                         
[12:56:27] 200 -    1KB - /dev/
[12:56:27] 301 -  308B  - /dev  ->  http://10.10.10.79/dev/
[12:56:28] 403 -  283B  - /doc/
[12:56:28] 403 -  298B  - /doc/en/changes.html
[12:56:28] 403 -  297B  - /doc/stable.version
[12:56:28] 403 -  287B  - /doc/api/
[12:56:28] 403 -  298B  - /doc/html/index.html
[12:56:32] 200 -   38B  - /index
[12:56:32] 200 -   38B  - /index.php
[12:56:33] 200 -   38B  - /index.php/login/
[12:56:45] 403 -  293B  - /server-status/
[12:56:45] 403 -  292B  - /server-status                                                                            
Task Completed
```