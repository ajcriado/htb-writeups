#### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Zipping-10.10.11.229]
└─$ sudo nmap -p 22,80 -sCV -A -T4 -O 10.10.11.229
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-13 15:58 CET
Nmap scan report for 10.10.11.229
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
|_  256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-title: Zipping | Watch store
|_http-server-header: Apache/2.4.54 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 (96%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), Linux 2.6.32 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   67.87 ms 10.10.14.1
2   67.92 ms 10.10.11.229

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.09 seconds
```

### Fuzzing

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://10.10.11.229:80/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                    
 (_||| _) (/_(_|| (_| )                                                                                             
                                                                                                                    
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_10.10.11.229_80/__23-11-13_16-01-47.txt

Target: http://10.10.11.229/

[16:01:47] Starting:                                                                                                
[16:01:50] 403 -  277B  - /.ht_wsr.txt                                      
[16:01:50] 403 -  277B  - /.htaccess.bak1                                   
[16:01:50] 403 -  277B  - /.htaccess.sample                                 
[16:01:50] 403 -  277B  - /.htaccess.save                                   
[16:01:50] 403 -  277B  - /.htaccess.orig                                   
[16:01:50] 403 -  277B  - /.htaccess_orig                                   
[16:01:50] 403 -  277B  - /.htaccess_extra
[16:01:50] 403 -  277B  - /.htaccess_sc
[16:01:50] 403 -  277B  - /.htaccessOLD
[16:01:50] 403 -  277B  - /.htaccessOLD2
[16:01:50] 403 -  277B  - /.htaccessBAK                                     
[16:01:50] 403 -  277B  - /.htm                                             
[16:01:50] 403 -  277B  - /.html                                            
[16:01:50] 403 -  277B  - /.htpasswd_test                                   
[16:01:50] 403 -  277B  - /.htpasswds                                       
[16:01:50] 403 -  277B  - /.httr-oauth
[16:01:51] 403 -  277B  - /.php                                             
[16:02:03] 301 -  313B  - /assets  ->  http://10.10.11.229/assets/          
[16:02:03] 200 -  510B  - /assets/                                          
[16:02:31] 403 -  277B  - /server-status                                    
[16:02:31] 403 -  277B  - /server-status/                                   
[16:02:32] 301 -  311B  - /shop  ->  http://10.10.11.229/shop/              
[16:02:39] 200 -    2KB - /upload.php                                       
[16:02:39] 403 -  277B  - /uploads/                                         
[16:02:39] 301 -  314B  - /uploads  ->  http://10.10.11.229/uploads/        
                                                                             
Task Completed
```