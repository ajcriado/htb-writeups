### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Devvortex-10.10.11.242]
└─$ sudo nmap -p 22,80 -sCV -A -T4 -O 10.10.11.242
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-25 20:15 CET
Nmap scan report for 10.10.11.242
Host is up (0.048s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 (96%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   41.15 ms 10.10.14.1
2   41.31 ms 10.10.11.242

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.83 seconds
```

### Fuzzing

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://devvortex.htb/ 
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )                                                                                             
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_devvortex.htb/__23-11-25_20-25-11.txt

Target: http://devvortex.htb/

[20:25:11] Starting:                                                                                                
[20:25:13] 301 -  178B  - /js  ->  http://devvortex.htb/js/                 
[20:25:22] 200 -    7KB - /about.html                                       
[20:25:41] 200 -    9KB - /contact.html                                     
[20:25:41] 301 -  178B  - /css  ->  http://devvortex.htb/css/               
[20:25:49] 403 -  564B  - /images/                                          
[20:25:49] 301 -  178B  - /images  ->  http://devvortex.htb/images/
[20:25:51] 403 -  564B  - /js/                                              

Task Completed

┌──(kali㉿kali)-[~]
└─$ gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://devvortex.htb --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://devvortex.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.devvortex.htb Status: 200 [Size: 23221]
Progress: 4989 / 4990 (99.98%)
===============================================================
Finished
===============================================================

┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://dev.devvortex.htb/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                    
 (_||| _) (/_(_|| (_| )                                                                                             
                                                                                                                    
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_dev.devvortex.htb/__23-11-25_20-26-33.txt

Target: http://dev.devvortex.htb/

[20:26:33] Starting:                                                                                                
[20:26:54] 403 -  564B  - /%2e%2e;/test                                     
[20:26:56] 404 -   16B  - /php                                              
[20:28:44] 404 -   16B  - /adminphp                                         
[20:28:49] 403 -  564B  - /admin/.config                                                                            
[20:29:29] 301 -  178B  - /administrator  ->  http://dev.devvortex.htb/administrator/                               
[20:29:30] 200 -   31B  - /administrator/cache/                                                                     
[20:29:30] 403 -  564B  - /administrator/includes/                                                                  
[20:29:30] 301 -  178B  - /administrator/logs  ->  http://dev.devvortex.htb/administrator/logs/
[20:29:30] 200 -   31B  - /administrator/logs/
[20:29:30] 200 -   12KB - /administrator/                                   
[20:29:31] 200 -   12KB - /administrator/index.php                          
[20:29:38] 403 -  564B  - /admpar/.ftppass                                  
[20:29:38] 403 -  564B  - /admrev/.ftppass                                  
[20:29:42] 301 -  178B  - /api  ->  http://dev.devvortex.htb/api/           
[20:29:43] 404 -   54B  - /api/                                             
[20:29:43] 404 -   54B  - /api/2/explore/                                   
[20:29:43] 404 -   54B  - /api/api
[20:29:43] 404 -   54B  - /api/2/issue/createmeta
[20:29:43] 404 -   54B  - /api/__swagger__/
[20:29:43] 404 -   54B  - /api/_swagger_/
[20:29:43] 404 -   54B  - /api/batch
[20:29:43] 404 -   54B  - /api/apidocs/swagger.json
[20:29:43] 404 -   54B  - /api/api-docs
[20:29:43] 404 -   54B  - /api/apidocs
[20:29:43] 404 -   54B  - /api/application.wadl
[20:29:43] 404 -   54B  - /api/config
[20:29:43] 404 -   54B  - /api/jsonws/invoke
[20:29:43] 404 -   54B  - /api/index.html
[20:29:43] 404 -   54B  - /api/jsonws
[20:29:43] 404 -   54B  - /api/docs
[20:29:43] 404 -   54B  - /api/docs/
[20:29:44] 404 -   54B  - /api/profile
[20:29:44] 404 -   54B  - /api/package_search/v4/documentation
[20:29:44] 404 -   54B  - /api/cask/graphql
[20:29:44] 404 -   54B  - /api/error_log
[20:29:44] 404 -   54B  - /api/proxy
[20:29:44] 404 -   54B  - /api/swagger.json
[20:29:44] 404 -   54B  - /api/login.json
[20:29:44] 404 -   54B  - /api/snapshots
[20:29:44] 404 -   54B  - /api/swagger-ui.html
[20:29:44] 404 -   54B  - /api/swagger
[20:29:44] 404 -   54B  - /api/swagger.yaml
[20:29:44] 404 -   54B  - /api/spec/swagger.json
[20:29:44] 404 -   54B  - /api/swagger/index.html
[20:29:44] 404 -   54B  - /api/swagger/static/index.html
[20:29:44] 404 -   54B  - /api/swagger.yml
[20:29:44] 404 -   54B  - /api/swagger/swagger
[20:29:44] 404 -   54B  - /api/swagger/ui/index
[20:29:44] 404 -   54B  - /api/v1/
[20:29:44] 404 -   54B  - /api/timelion/run
[20:29:44] 404 -   54B  - /api/v1/swagger.json
[20:29:44] 404 -   54B  - /api/v1
[20:29:44] 404 -   54B  - /api/v1/swagger.yaml
[20:29:44] 404 -   54B  - /api/v2
[20:29:44] 404 -   54B  - /api/v2/helpdesk/discover
[20:29:44] 404 -   54B  - /api/v2/swagger.yaml
[20:29:44] 404 -   54B  - /api/v2/swagger.json
[20:29:44] 404 -   54B  - /api/v2/
[20:29:44] 404 -   54B  - /api/vendor/phpunit/phpunit/phpunit
[20:29:44] 404 -   54B  - /api/version
[20:29:45] 404 -   54B  - /api/v3                                           
[20:29:45] 404 -   54B  - /api/whoami
[20:29:45] 404 -   54B  - /api/v4                                           
[20:30:01] 403 -  564B  - /bitrix/.settings.bak                             
[20:30:01] 403 -  564B  - /bitrix/.settings.php.bak
[20:30:01] 403 -  564B  - /bitrix/.settings
[20:30:07] 301 -  178B  - /cache  ->  http://dev.devvortex.htb/cache/       
[20:30:07] 200 -   31B  - /cache/                                           
[20:30:08] 403 -    4KB - /cache/sql_error_latest.cgi                       
[20:30:16] 200 -   31B  - /cli/                                             
[20:30:21] 301 -  178B  - /components  ->  http://dev.devvortex.htb/components/
[20:30:21] 200 -   31B  - /components/
[20:30:27] 200 -    0B  - /configuration.php                                
[20:31:01] 403 -  564B  - /ext/.deps                                        
[20:31:22] 200 -    7KB - /htaccess.txt                                     
[20:31:26] 301 -  178B  - /images  ->  http://dev.devvortex.htb/images/     
[20:31:26] 200 -   31B  - /images/                                          
[20:31:27] 403 -    4KB - /images/c99.php                                   
[20:31:27] 403 -    4KB - /images/Sym.php                                   
[20:31:28] 301 -  178B  - /includes  ->  http://dev.devvortex.htb/includes/ 
[20:31:28] 200 -   31B  - /includes/                                        
[20:31:43] 301 -  178B  - /language  ->  http://dev.devvortex.htb/language/ 
[20:31:43] 200 -   31B  - /layouts/                                         
[20:31:44] 403 -  564B  - /lib/flex/uploader/.flexProperties                
[20:31:44] 403 -  564B  - /lib/flex/uploader/.project
[20:31:44] 403 -  564B  - /lib/flex/uploader/.actionScriptProperties
[20:31:44] 403 -  564B  - /lib/flex/uploader/.settings                      
[20:31:44] 403 -  564B  - /lib/flex/varien/.project                         
[20:31:44] 403 -  564B  - /lib/flex/varien/.settings
[20:31:44] 403 -  564B  - /lib/flex/varien/.actionScriptProperties
[20:31:44] 403 -  564B  - /lib/flex/varien/.flexLibProperties
[20:31:44] 200 -   31B  - /libraries/                                       
[20:31:44] 301 -  178B  - /libraries  ->  http://dev.devvortex.htb/libraries/
[20:31:45] 200 -   18KB - /LICENSE.txt                                      
[20:31:55] 403 -  564B  - /mailer/.env                                      
[20:32:00] 301 -  178B  - /media  ->  http://dev.devvortex.htb/media/       
[20:32:00] 200 -   31B  - /media/                                           
[20:32:09] 200 -   31B  - /modules/                                         
[20:32:09] 301 -  178B  - /modules  ->  http://dev.devvortex.htb/modules/
[20:32:12] 404 -   16B  - /myadminphp                                       
[20:32:42] 301 -  178B  - /plugins  ->  http://dev.devvortex.htb/plugins/   
[20:32:42] 200 -   31B  - /plugins/                                         
[20:32:54] 200 -    5KB - /README.txt                                       
[20:32:58] 403 -  564B  - /resources/.arch-internal-preview.css             
[20:32:58] 403 -  564B  - /resources/sass/.sass-cache/                      
[20:33:00] 200 -  764B  - /robots.txt                                       
[20:33:06] 404 -    4KB - /secure/ConfigurePortalPages!default.jspa?view=popular
[20:33:37] 301 -  178B  - /templates  ->  http://dev.devvortex.htb/templates/
[20:33:37] 200 -   31B  - /templates/
[20:33:37] 200 -   31B  - /templates/index.html                             
[20:33:38] 200 -    0B  - /templates/system/                                
[20:33:42] 301 -  178B  - /tmp  ->  http://dev.devvortex.htb/tmp/           
[20:33:42] 200 -   31B  - /tmp/
[20:33:43] 403 -    4KB - /tmp/2.php                                        
[20:33:43] 403 -    4KB - /tmp/admin.php                                    
[20:33:43] 403 -    4KB - /tmp/cgi.pl                                       
[20:33:43] 403 -    4KB - /tmp/Cgishell.pl                                  
[20:33:44] 403 -    4KB - /tmp/d.php
[20:33:44] 403 -    4KB - /tmp/cpn.php
[20:33:44] 403 -    4KB - /tmp/domaine.pl
[20:33:44] 403 -    4KB - /tmp/changeall.php
[20:33:44] 403 -    4KB - /tmp/d0maine.php
[20:33:44] 403 -    4KB - /tmp/domaine.php
[20:33:44] 403 -    4KB - /tmp/dz1.php                                      
[20:33:44] 403 -    4KB - /tmp/dz.php                                       
[20:33:44] 403 -    4KB - /tmp/killer.php
[20:33:44] 403 -    4KB - /tmp/index.php
[20:33:44] 403 -    4KB - /tmp/L3b.php
[20:33:44] 403 -    4KB - /tmp/madspotshell.php
[20:33:44] 403 -    4KB - /tmp/up.php                                       
[20:33:44] 403 -    4KB - /tmp/Sym.php
[20:33:44] 403 -    4KB - /tmp/uploads.php
[20:33:44] 403 -    4KB - /tmp/sql.php
[20:33:44] 403 -    4KB - /tmp/root.php                                     
[20:33:44] 403 -    4KB - /tmp/priv8.php
[20:33:44] 403 -    4KB - /tmp/upload.php                                   
[20:33:44] 403 -    4KB - /tmp/vaga.php
[20:33:44] 403 -    4KB - /tmp/user.php
[20:33:45] 403 -    4KB - /tmp/xd.php
[20:33:45] 403 -    4KB - /tmp/whmcs.php
[20:33:45] 403 -  564B  - /twitter/.env                                     
[20:34:05] 200 -    3KB - /web.config.txt                                   
                                                                             
Task Completed
```