### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Poison-10.10.10.84]
└─$ sudo nmap -p 22,80 10.10.10.84 -sCV -A -T4 -O
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-30 16:39 CEST
Nmap scan report for 10.10.10.84
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: FreeBSD 11.0-RELEASE - 12.0-CURRENT (97%), FreeBSD 11.1-STABLE (97%), FreeBSD 11.1-RELEASE or 11.2-STABLE (96%), FreeBSD 11.2-RELEASE - 11.3 RELEASE or 11.2-STABLE (96%), FreeBSD 11.3-RELEASE (96%), FreeBSD 11.1-RELEASE (95%), FreeBSD 11.0-STABLE (94%), FreeBSD 11.0-CURRENT (94%), FreeBSD 11.0-RELEASE (94%), FreeBSD 12.0-RELEASE - 13.0-CURRENT (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   88.61 ms 10.10.14.1
2   98.94 ms 10.10.10.84

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.23 seconds
```