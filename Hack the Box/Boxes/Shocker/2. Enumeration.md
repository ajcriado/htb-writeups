### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Shocker-10.10.10.56]
└─$ sudo nmap -p 80,2222 -sCV -A -T4 -O 10.10.10.56                                                 
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-29 11:39 CET
Nmap scan report for 10.10.10.56
Host is up (0.049s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesnt have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.12 (96%), Linux 3.13 (96%), Linux 3.2 - 4.9 (96%), Linux 3.8 - 3.11 (96%), Linux 4.8 (96%), Linux 4.4 (95%), Linux 4.9 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 4.2 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   42.29 ms 10.10.14.1
2   42.45 ms 10.10.10.56

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.57 seconds
```

### Fuzzing

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://10.10.10.56:80/    

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927
Output File: /home/kali/.dirsearch/reports/10.10.10.56-80/-_23-10-29_11-38-28.txt
Error Log: /home/kali/.dirsearch/logs/errors-23-10-29_11-38-28.log

Target: http://10.10.10.56:80/

[11:38:28] Starting: 
[11:38:31] 403 -  297B  - /.ht_wsr.txt                                     
[11:38:31] 403 -  300B  - /.htaccess.bak1                                  
[11:38:31] 403 -  291B  - /.html
[11:38:31] 403 -  290B  - /.htm
[11:38:31] 403 -  301B  - /.htaccess_extra
[11:38:31] 403 -  300B  - /.htaccess_orig
[11:38:31] 403 -  300B  - /.htaccess.orig
[11:38:31] 403 -  300B  - /.htaccess.save
[11:38:31] 403 -  298B  - /.htaccess_sc
[11:38:31] 403 -  298B  - /.htaccessBAK
[11:38:31] 403 -  299B  - /.htaccessOLD2                                   
[11:38:31] 403 -  298B  - /.htaccessOLD
[11:38:31] 403 -  297B  - /.httr-oauth
[11:38:31] 403 -  300B  - /.htpasswd_test
[11:38:31] 403 -  296B  - /.htpasswds
[11:38:31] 403 -  302B  - /.htaccess.sample
[11:38:48] 403 -  294B  - /cgi-bin/                                         
[11:38:56] 200 -  137B  - /index.html                                       
[11:39:09] 403 -  299B  - /server-status                                    
[11:39:09] 403 -  300B  - /server-status/
                                                                             
Task Completed
```

Giving the cgi-bin folder, after fuzzing the folder for scripts we found the user.sh script

```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.10.10.56/cgi-bin/FUZZ.sh 

        /'___\  /'___\           /'___'\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.56/cgi-bin/FUZZ.sh
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

user                    [Status: 200, Size: 119]
:: Progress: [4614/4614] :: Job [1/1] :: 938 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```