### Nmap
**TCP**

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Mirai-10.10.10.48]
└─$ sudo nmap -p 22,53,80,1659,32400,32469 -sVC -A -T4 -O 10.10.10.48
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-29 16:27 CET
Nmap scan report for 10.10.10.48
Host is up (0.045s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
|_  256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
53/tcp    open  domain  dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp    open  http    lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Site doesnt have a title (text/html; charset=UTF-8).
1659/tcp  open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
32400/tcp open  http    Plex Media Server httpd
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-favicon: Plex
|_http-cors: HEAD GET POST PUT DELETE OPTIONS
|_http-title: Unauthorized
32469/tcp open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.13 (96%), Linux 3.2 - 4.9 (96%), Linux 4.8 (96%), Linux 4.9 (95%), Linux 3.16 (95%), Linux 3.12 (95%), Linux 3.8 - 3.11 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 4.4 (95%), Linux 3.18 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   44.09 ms 10.10.14.1
2   44.21 ms 10.10.10.48

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.50 seconds
```

**UDP**

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p 53,123,5353,32414 -sU -sCV -A -T4 10.10.10.48                                                  
Nmap scan report for 10.10.10.48
Host is up (0.045s latency).

PORT      STATE SERVICE VERSION
53/udp    open  domain  dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
123/udp   open  ntp     NTP v4 (unsynchronized)
| ntp-info: 
|_  
5353/udp  open  mdns    DNS-based service discovery
| dns-service-discovery: 
|   9/tcp workstation
|     Address=10.10.10.48 dead:beef::e9f0:a0ca:c5fe:61ff
|   22/tcp udisks-ssh
|_    Address=10.10.10.48 dead:beef::e9f0:a0ca:c5fe:61ff
32414/udp open  unknown
Too many fingerprints match this host to give specific OS details
Network Distance: 2 hops

Host script results:
|_clock-skew: 6s

TRACEROUTE (using port 32414/udp)
HOP RTT      ADDRESS
1   46.31 ms 10.10.14.1
2   46.70 ms 10.10.10.48

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 141.22 seconds
```

### Fuzzing

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://10.10.10.48:80/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )                                                                                             
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/10.10.10.48-80/-_23-10-29_16-37-43.txt

Error Log: /home/kali/.dirsearch/logs/errors-23-10-29_16-37-43.log

Target: http://10.10.10.48:80/

[16:37:43] Starting: 
[16:37:54] 301 -    0B  - /admin  ->  http://10.10.10.48/admin/             
[16:38:19] 500 -  369B  - /admloginuser.aspx                                 
[16:38:19] 500 -  369B  - /admission_controller_config.yaml
[...SNIP...]
```

