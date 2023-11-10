### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Academy/Attacking-common-services/lab-medium]
└─$ sudo nmap -p22,53,110,995,2121,30021 -sCV -A -T4 -O 10.129.143.32
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 12:01 CEST
Stats: 0:02:49 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.16% done; ETC: 12:04 (0:00:00 remaining)
Nmap scan report for 10.129.143.32
Host is up (0.091s latency).

PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
53/tcp    open  domain       ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
110/tcp   open  pop3         Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: RESP-CODES UIDL PIPELINING AUTH-RESP-CODE CAPA SASL(PLAIN) TOP USER STLS
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-04-11T16:38:55
|_Not valid after:  2032-04-08T16:38:55
995/tcp   open  ssl/pop3     Dovecot pop3d
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-04-11T16:38:55
|_Not valid after:  2032-04-08T16:38:55
|_pop3-capabilities: CAPA SASL(PLAIN) RESP-CODES UIDL USER PIPELINING TOP AUTH-RESP-CODE
|_ssl-date: TLS randomness does not represent time
2121/tcp  open  ccproxy-ftp?
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (InlaneFTP) [10.129.143.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
30021/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Internal FTP) [10.129.143.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2121-TCP:V=7.94%I=7%D=8/18%Time=64DF419F%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,8C,"220\x20ProFTPD\x20Server\x20\(InlaneFTP\)\x20\[10\.129\.
SF:143\.32\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20crea
SF:tive\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creative\
SF:r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port30021-TCP:V=7.94%I=7%D=8/18%Time=64DF419F%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,8F,"220\x20ProFTPD\x20Server\x20\(Internal\x20FTP\)\x20\[10
SF:\.129\.143\.32\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\
SF:x20creative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cr
SF:eative\r\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   117.69 ms 10.10.16.1
2   118.17 ms 10.129.143.32

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 191.37 seconds
```