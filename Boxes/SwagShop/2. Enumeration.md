### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/SwagShop-10.10.10.140]
└─$ sudo nmap -p 22,80 -sCV -A -T4 -O 10.10.10.140 
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-05 21:57 CET
Nmap scan report for 10.10.10.140
Host is up (0.037s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Did not follow redirect to http://swagshop.htb/
|_http-server-header: Apache/2.4.29 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   36.78 ms 10.10.14.1
2   36.83 ms 10.10.10.140

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.50 seconds
```

### Fuzzing

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://swagshop.htb

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/swagshop.htb/_23-11-05_22-01-06.txt

Error Log: /home/kali/.dirsearch/logs/errors-23-11-05_22-01-06.log

Target: http://swagshop.htb/

[22:01:06] Starting: 
[22:01:08] 301 -  309B  - /js  ->  http://swagshop.htb/js/                 
[22:01:08] 403 -  277B  - /.ht_wsr.txt                                     
[22:01:08] 403 -  277B  - /.htaccess.bak1
[22:01:08] 403 -  277B  - /.htaccess.save
[22:01:08] 403 -  277B  - /.htaccess_sc
[22:01:08] 403 -  277B  - /.htaccess_extra
[22:01:08] 403 -  277B  - /.htaccess_orig
[22:01:08] 403 -  277B  - /.htaccessOLD                                    
[22:01:08] 403 -  277B  - /.htm
[22:01:08] 403 -  277B  - /.htaccessBAK
[22:01:08] 403 -  277B  - /.html
[22:01:08] 403 -  277B  - /.htaccessOLD2
[22:01:08] 403 -  277B  - /.htpasswd_test
[22:01:08] 403 -  277B  - /.httr-oauth
[22:01:08] 403 -  277B  - /.htpasswds                                      
[22:01:09] 403 -  277B  - /.htaccess.orig                                  
[22:01:09] 403 -  277B  - /.htaccess.sample                                
[22:01:09] 403 -  277B  - /.php                                            
[22:01:09] 403 -  277B  - /.php3                                           
[22:01:12] 200 -   10KB - /LICENSE.txt                                      
[22:01:19] 200 -  571KB - /RELEASE_NOTES.txt                                
[22:01:25] 200 -   37B  - /api.php                                          
[22:01:25] 301 -  310B  - /app  ->  http://swagshop.htb/app/                
[22:01:25] 403 -  277B  - /app/.htaccess                                    
[22:01:25] 200 -    2KB - /app/                                             
[22:01:25] 200 -    2KB - /app/etc/local.xml                                
[22:01:25] 200 -    9KB - /app/etc/local.xml.additional                     
[22:01:25] 200 -    5KB - /app/etc/config.xml
[22:01:25] 200 -    2KB - /app/etc/local.xml.template                       
[22:01:29] 200 -    0B  - /cron.php                                         
[22:01:29] 200 -  717B  - /cron.sh                                          
[22:01:32] 301 -  313B  - /errors  ->  http://swagshop.htb/errors/          
[22:01:32] 200 -    2KB - /errors/                                          
[22:01:32] 200 -    1KB - /favicon.ico                                      
[22:01:35] 200 -  946B  - /includes/                                        
[22:01:35] 301 -  315B  - /includes  ->  http://swagshop.htb/includes/      
[22:01:35] 200 -   16KB - /index.php                                        
[22:01:35] 200 -   44B  - /install.php                                      
[22:01:36] 301 -  318B  - /js/tiny_mce  ->  http://swagshop.htb/js/tiny_mce/
[22:01:36] 200 -    4KB - /js/tiny_mce/                                     
[22:01:37] 301 -  310B  - /lib  ->  http://swagshop.htb/lib/                
[22:01:37] 200 -    3KB - /lib/                                             
[22:01:38] 301 -  312B  - /media  ->  http://swagshop.htb/media/            
[22:01:38] 200 -    2KB - /media/                                           
[22:01:42] 200 -  886B  - /php.ini.sample                                   
[22:01:43] 301 -  314B  - /pkginfo  ->  http://swagshop.htb/pkginfo/        
[22:01:46] 403 -  277B  - /server-status                                    
[22:01:46] 403 -  277B  - /server-status/                                   
[22:01:47] 301 -  312B  - /shell  ->  http://swagshop.htb/shell/            
[22:01:47] 200 -    2KB - /shell/                                           
[22:01:47] 301 -  311B  - /skin  ->  http://swagshop.htb/skin/              
[22:01:52] 301 -  310B  - /var  ->  http://swagshop.htb/var/                
[22:01:52] 200 -    4KB - /var/cache/
[22:01:52] 200 -    2KB - /var/                                             
[22:01:52] 200 -  755B  - /var/backups/                                     
[22:01:52] 200 -    9KB - /var/package/                                     
                                                                             
Task Completed
```