### Nmap 

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p 21,22,80,25565 -sCV -A -T4 -O 10.10.10.37    
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-05 13:06 CET
Nmap scan report for 10.10.10.37
Host is up (0.047s latency).

PORT      STATE SERVICE   VERSION
21/tcp    open  ftp       ProFTPD 1.3.5a
22/tcp    open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp    open  http      Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Did not follow redirect to http://blocky.htb
25565/tcp open  minecraft Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|phone|storage-misc
Running (JUST GUESSING): Linux 3.X|4.X|5.X (90%), Crestron 2-Series (86%), Google Android 4.X (86%), HP embedded (85%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:crestron:2_series cpe:/o:google:android:4.0 cpe:/o:linux:linux_kernel:5.0 cpe:/h:hp:p2000_g3
Aggressive OS guesses: Linux 3.10 - 4.11 (90%), Linux 3.12 (90%), Linux 3.13 (90%), Linux 3.13 or 4.2 (90%), Linux 3.16 - 4.6 (90%), Linux 3.2 - 4.9 (90%), Linux 3.8 - 3.11 (90%), Linux 4.2 (90%), Linux 4.4 (90%), Linux 3.16 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   46.53 ms 10.10.14.1
2   46.65 ms 10.10.10.37

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.71 seconds
```

### Fuzzing

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://blocky.htb/

  _|. _ _  _  _  _ _|_    v0.4.2                                                                                    
 (_||| _) (/_(_|| (_| )                                                                                             
                                                                                                                    
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/blocky.htb/-_23-11-05_13-30-57.txt

Error Log: /home/kali/.dirsearch/logs/errors-23-11-05_13-30-57.log

Target: http://blocky.htb/

[13:30:58] Starting: 
[13:31:01] 403 -  296B  - /.ht_wsr.txt                                     
[13:31:01] 403 -  299B  - /.htaccess.bak1
[13:31:01] 403 -  301B  - /.htaccess.sample
[13:31:01] 403 -  299B  - /.htaccess.orig
[13:31:01] 403 -  299B  - /.htaccess.save
[13:31:01] 403 -  300B  - /.htaccess_extra
[13:31:01] 403 -  299B  - /.htaccess_orig
[13:31:01] 403 -  297B  - /.htaccess_sc
[13:31:01] 403 -  297B  - /.htaccessBAK                                    
[13:31:01] 403 -  298B  - /.htaccessOLD2
[13:31:01] 403 -  297B  - /.htaccessOLD
[13:31:01] 403 -  289B  - /.htm
[13:31:01] 403 -  290B  - /.html
[13:31:01] 403 -  299B  - /.htpasswd_test
[13:31:01] 403 -  295B  - /.htpasswds
[13:31:01] 403 -  296B  - /.httr-oauth                                     
[13:31:02] 403 -  289B  - /.php                                            
[13:31:02] 403 -  290B  - /.php3                                           
[13:31:27] 301 -    0B  - /index.php  ->  http://blocky.htb/                
[13:31:28] 301 -  313B  - /javascript  ->  http://blocky.htb/javascript/    
[13:31:29] 200 -   19KB - /license.txt                                      
[13:31:34] 200 -   13KB - /phpmyadmin/doc/html/index.html                   
[13:31:34] 301 -  313B  - /phpmyadmin  ->  http://blocky.htb/phpmyadmin/    
[13:31:36] 200 -   10KB - /phpmyadmin/                                      
[13:31:36] 200 -   10KB - /phpmyadmin/index.php                             
[13:31:36] 200 -  745B  - /plugins/                                         
[13:31:36] 301 -  310B  - /plugins  ->  http://blocky.htb/plugins/          
[13:31:37] 200 -    7KB - /readme.html                                      
[13:31:39] 403 -  299B  - /server-status/                                   
[13:31:39] 403 -  298B  - /server-status
[13:31:46] 301 -  307B  - /wiki  ->  http://blocky.htb/wiki/                
[13:31:46] 200 -  380B  - /wiki/                                            
[13:31:46] 301 -  311B  - /wp-admin  ->  http://blocky.htb/wp-admin/        
[13:31:46] 200 -    0B  - /wp-config.php
[13:31:46] 200 -    1B  - /wp-admin/admin-ajax.php                          
[13:31:47] 302 -    0B  - /wp-admin/  ->  http://blocky.htb/wp-login.php?redirect_to=http%3A%2F%2Fblocky.htb%2Fwp-admin%2F&reauth=1
[13:31:47] 200 -    0B  - /wp-content/                                      
[13:31:47] 500 -    4KB - /wp-admin/setup-config.php                        
[13:31:47] 200 -    1KB - /wp-admin/install.php
[13:31:47] 301 -  313B  - /wp-content  ->  http://blocky.htb/wp-content/    
[13:31:47] 200 -   69B  - /wp-content/plugins/akismet/akismet.php           
[13:31:47] 500 -    0B  - /wp-content/plugins/hello.php                     
[13:31:47] 200 -  964B  - /wp-content/uploads/                              
[13:31:47] 301 -  314B  - /wp-includes  ->  http://blocky.htb/wp-includes/  
[13:31:47] 302 -    0B  - /wp-signup.php  ->  http://blocky.htb/wp-login.php?action=register
[13:31:47] 200 -    2KB - /wp-login.php                                     
[13:31:47] 200 -    0B  - /wp-cron.php                                      
[13:31:47] 500 -    0B  - /wp-includes/rss-functions.php                    
[13:31:47] 200 -   40KB - /wp-includes/                                     
[13:31:47] 405 -   42B  - /xmlrpc.php                                       
                                                                             
Task Completed                     
```