## Nmap scans

### Default scan
``` bash
# Nmap 7.94 scan initiated Mon Jul  3 09:32:28 2023 as: nmap -p- --min-rate 5000 -oA nmap/default-scan 10.129.222.23
Nmap scan report for 10.129.222.23
Host is up (0.042s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
53/tcp   open  domain
2121/tcp open  ccproxy-ftp

# Nmap done at Mon Jul  3 09:32:41 2023 -- 1 IP address (1 host up) scanned in 13.22 seconds
```

### UDP scan
```bash
# Nmap 7.94 scan initiated Mon Jul  3 09:45:12 2023 as: nmap -sU -p- --min-rate 5000 -oA nmap/udp-scan 10.129.222.23
Warning: 10.129.222.23 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.222.23
Host is up (0.045s latency).
Not shown: 65384 open|filtered udp ports (no-response), 149 closed udp ports (port-unreach)
PORT    STATE SERVICE
53/udp  open  domain
623/udp open  asf-rmcp

# Nmap done at Mon Jul  3 09:47:37 2023 -- 1 IP address (1 host up) scanned in 144.96 seconds
```

### Script and Services
``` bash
# Nmap 7.94 scan initiated Mon Jul  3 09:34:03 2023 as: nmap -p 21,22,53,2121 -sVC -oA nmap/script-and-services 10.129.222.23
Nmap scan report for 10.129.222.23
Host is up (0.044s latency).

PORT     STATE SERVICE      VERSION
21/tcp   open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (ftp.int.inlanefreight.htb) [10.129.222.23]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp   open  ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
53/tcp   open  domain       ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
2121/tcp open  ccproxy-ftp?
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Ceil's FTP) [10.129.222.23]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port21-TCP:V=7.94%I=7%D=7/3%Time=64A279F6%P=x86_64-pc-linux-gnu%r(Gener
SF:icLines,9C,"220\x20ProFTPD\x20Server\x20\(ftp\.int\.inlanefreight\.htb\
SF:)\x20\[10\.129\.222\.23\]\r\n500\x20Invalid\x20command:\x20try\x20being
SF:\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x20being\x20m
SF:ore\x20creative\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2121-TCP:V=7.94%I=7%D=7/3%Time=64A279F6%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,8D,"220\x20ProFTPD\x20Server\x20\(Ceil's\x20FTP\)\x20\[10\.12
SF:9\.222\.23\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20c
SF:reative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creati
SF:ve\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul  3 09:37:20 2023 -- 1 IP address (1 host up) scanned in 197.42 seconds
```

```bash
# Nmap 7.94 scan initiated Mon Jul  3 09:55:08 2023 as: nmap -sU -p 623 -sVC -oA nmap/script-and-services-udp 10.129.222.23
Nmap scan report for 10.129.222.23
Host is up (0.044s latency).

PORT    STATE SERVICE  VERSION
623/udp open  asf-rmcp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port623-UDP:V=7.94%I=7%D=7/3%Time=64A27EE2%P=x86_64-pc-linux-gnu%r(ipmi
SF:-rmcp,1E,"\x06\0\xff\x07\0\0\0\0\0\0\0\0\0\x10\x81\x1cc\x20\x008\0\x01\
SF:x97\x04\x03\0\0\0\0\t");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul  3 09:55:14 2023 -- 1 IP address (1 host up) scanned in 5.57 seconds
```