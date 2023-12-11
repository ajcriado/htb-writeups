### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Buff-10.10.10.198]
└─$ sudo nmap -p 7680,8080 -sCV -A -T4 -O 10.10.10.198 -Pn
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-07 12:53 CET
Nmap scan report for 10.10.10.198
Host is up (0.070s latency).

PORT     STATE SERVICE    VERSION
7680/tcp open  pando-pub?
8080/tcp open  http       Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: mrb3ns Bro Hut
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP (85%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: Microsoft Windows XP SP3 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   37.17 ms  10.10.14.1
2   171.02 ms 10.10.10.198

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.97 seconds
```

### Fuzzing

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://10.10.10.198:8080/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/10.10.10.198-8080/-_23-11-07_12-55-29.txt

Error Log: /home/kali/.dirsearch/logs/errors-23-11-07_12-55-29.log

Target: http://10.10.10.198:8080/

[12:55:30] Starting: 
[12:55:31] 403 -    1KB - /%C0%AE%C0%AE%C0%AF                              
[12:55:31] 403 -    1KB - /%3f/                                            
[12:55:31] 403 -    1KB - /%ff                                             
[12:55:32] 403 -    1KB - /.fishsrv.pl                                     
[12:55:33] 200 -   66B  - /.gitattributes                                  
[12:55:34] 403 -    1KB - /.ht_wsr.txt                                     
[12:55:34] 403 -    1KB - /.htaccess.bak1                                  
[12:55:34] 403 -    1KB - /.htaccessBAK                                    
[12:55:34] 403 -    1KB - /.htaccess.save                                  
[12:55:34] 403 -    1KB - /.htpasswd_test
[12:55:34] 403 -    1KB - /.htaccess_sc
[12:55:34] 403 -    1KB - /.htaccess_extra
[12:55:34] 403 -    1KB - /.htaccessOLD
[12:55:34] 403 -    1KB - /.htpasswds
[12:55:34] 403 -    1KB - /.htaccess_orig
[12:55:34] 403 -    1KB - /.htm
[12:55:34] 403 -    1KB - /.htaccessOLD2
[12:55:34] 403 -    1KB - /.htaccess.orig
[12:55:34] 403 -    1KB - /.html
[12:55:34] 403 -    1KB - /.httr-oauth
[12:55:34] 403 -    1KB - /.htaccess.sample
[12:55:40] 403 -    1KB - /.ssh.asp                                         
[12:55:47] 403 -    1KB - /AT-admin.cgi                                     
[12:55:48] 403 -    1KB - /Cgishell.pl                                      
[12:55:50] 200 -   18KB - /LICENSE                                          
[12:55:51] 200 -  309B  - /ReadMe.md                                        
[12:55:51] 200 -  309B  - /Readme.md                                        
[12:55:51] 200 -  309B  - /README.MD                                        
[12:55:51] 200 -  309B  - /README.md                                        
[12:55:53] 403 -    1KB - /Trace.axd::$DATA                                 
[12:55:53] 301 -  344B  - /Upload  ->  http://10.10.10.198:8080/Upload/     
[12:55:55] 403 -    1KB - /WebShell.cgi                                     
[12:55:58] 403 -    1KB - /accounts.cgi                                     
[12:55:58] 403 -    1KB - /accounts.pl                                      
[12:55:59] 200 -    5KB - /about.php                                        
[12:56:00] 403 -    1KB - /adm.pl                                           
[12:56:00] 403 -    1KB - /adm.cgi                                          
[12:56:01] 403 -    1KB - /admin.pl                                         
[12:56:01] 403 -    1KB - /admin.asp                                        
[12:56:01] 403 -    1KB - /admin.cgi                                        
[12:56:17] 403 -    1KB - /apply.cgi                                        
[12:56:18] 403 -    1KB - /auth.pl                                          
[12:56:18] 403 -    1KB - /auth.cgi                                         
[12:56:18] 403 -    1KB - /awstats.pl                                       
[12:56:22] 403 -    1KB - /cachemgr.cgi                                     
[12:56:22] 403 -    1KB - /cgi-bin/                                         
[12:56:23] 403 -    1KB - /cgi.pl/                                          
[12:56:24] 403 -    1KB - /cmdasp.asp                                       
[12:56:24] 403 -    1KB - /cmd-asp-5.1.asp                                  
[12:56:24] 200 -    1KB - /cgi-bin/printenv.pl                              
[12:56:27] 403 -    1KB - /conn.asp                                         
[12:56:29] 200 -    4KB - /contact.php                                      
[12:56:30] 403 -    1KB - /dcadmin.cgi                                      
[12:56:34] 403 -    1KB - /error.asp                                        
[12:56:34] 403 -    1KB - /error/                                           
[12:56:34] 200 -    4KB - /edit.php                                         
[12:56:35] 403 -    1KB - /errors.asp                                       
[12:56:36] 403 -    1KB - /file_upload.asp                                  
[12:56:36] 503 -    1KB - /examples/servlets/servlet/CookieExample          
[12:56:36] 503 -    1KB - /examples/                                        
[12:56:36] 503 -    1KB - /examples/jsp/%252e%252e/%252e%252e/manager/html/ 
[12:56:36] 503 -    1KB - /examples
[12:56:36] 503 -    1KB - /examples/servlet/SnoopServlet                    
[12:56:36] 503 -    1KB - /examples/servlets/index.html
[12:56:36] 503 -    1KB - /examples/servlets/servlet/RequestHeaderExample   
[12:56:36] 503 -    1KB - /examples/jsp/snp/snoop.jsp
[12:56:38] 200 -    4KB - /feedback.php                                     
[12:56:38] 403 -    1KB - /gbpass.pl                                        
[12:56:40] 403 -    1KB - /hndUnblock.cgi                                   
[12:56:40] 200 -  143B  - /home.php                                         
[12:56:41] 301 -  341B  - /img  ->  http://10.10.10.198:8080/img/           
[12:56:41] 301 -  345B  - /include  ->  http://10.10.10.198:8080/include/   
[12:56:42] 403 -    1KB - /include/                                         
[12:56:42] 403 -    1KB - /index.php::$DATA                                 
[12:56:43] 403 -    1KB - /install.asp                                      
[12:56:43] 200 -    5KB - /index.php                                        
[12:56:43] 200 -    5KB - /index.pHp                                        
[12:56:43] 200 -    5KB - /index.php.                                       
[12:56:43] 200 -    5KB - /index.php/login/
[12:56:46] 200 -   18KB - /license                                          
[12:56:47] 403 -    1KB - /login.cgi                                        
[12:56:47] 403 -    1KB - /login.pl                                         
[12:56:47] 403 -    1KB - /login.asp                                        
[12:56:48] 403 -    1KB - /logout.asp                                       
[12:56:48] 403 -    1KB - /logs.pl                                          
[12:56:50] 403 -    1KB - /members.pl                                       
[12:56:50] 403 -    1KB - /members.cgi                                      
[12:56:52] 403 -    1KB - /mt-check.cgi                                     
[12:56:55] 403 -    1KB - /out.cgi                                          
[12:56:56] 403 -    1KB - /perl-reverse-shell.pl                            
[12:56:56] 403 -    1KB - /perlcmd.cgi                                      
[12:56:57] 403 -    1KB - /phpmyadmin/ChangeLog                             
[12:56:57] 403 -    1KB - /phpmyadmin/docs/html/index.html                  
[12:56:57] 403 -    1KB - /phpmyadmin/README                                
[12:56:57] 403 -    1KB - /phpmyadmin/doc/html/index.html                   
[12:56:58] 403 -    1KB - /phpmyadmin                                       
[12:57:00] 403 -    1KB - /phpmyadmin/phpmyadmin/index.php                  
[12:57:00] 403 -    1KB - /phpmyadmin/index.php
[12:57:00] 403 -    1KB - /phpmyadmin/                                      
[12:57:00] 403 -    1KB - /phpmyadmin/scripts/setup.php                     
[12:57:02] 301 -  345B  - /profile  ->  http://10.10.10.198:8080/profile/   
[12:57:03] 403 -    1KB - /ps_admin.cgi                                     
[12:57:03] 200 -  309B  - /readme.md                                        
[12:57:05] 200 -  137B  - /register.php                                     
[12:57:07] 403 -    1KB - /server-status/                                   
[12:57:07] 403 -    1KB - /server-info                                      
[12:57:07] 403 -    1KB - /server-status                                    
[12:57:08] 403 -    1KB - /showcode.asp                                     
[12:57:09] 403 -    1KB - /signin.pl                                        
[12:57:09] 403 -    1KB - /signin.cgi                                       
[12:57:14] 403 -    1KB - /test.asp                                         
[12:57:16] 200 -  209B  - /up.php                                           
[12:57:16] 301 -  344B  - /upload  ->  http://10.10.10.198:8080/upload/     
[12:57:16] 403 -    1KB - /upload.asp                                       
[12:57:16] 403 -    1KB - /upload/                                          
[12:57:17] 403 -    1KB - /uploadfile.asp                                   
[12:57:17] 403 -    1KB - /user.asp                                         
[12:57:18] 200 -  107B  - /upload.php                                       
[12:57:20] 403 -    1KB - /web.config::$DATA                                
[12:57:20] 403 -    1KB - /webalizer                                        
                                                                             
Task Completed
```