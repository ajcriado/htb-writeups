```bash
┌──(kali㉿kali)-[/Shared/htb-writeups]
└─$ for i in $(seq 254); do ping 10.10.110.$i -c1 -W1 & done | grep from 
64 bytes from 10.10.110.2: icmp_seq=1 ttl=64 time=55.6 ms
64 bytes from 10.10.110.100: icmp_seq=1 ttl=62 time=76.4 ms
```

### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Dante-Prolab]
└─$ nmap -p- -iL scope -oG nmap/fast-scan -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-30 21:30 CET
Stats: 0:01:15 elapsed; 0 hosts completed (2 up), 2 undergoing Connect Scan
Connect Scan Timing: About 28.37% done; ETC: 21:35 (0:03:09 remaining)
Stats: 0:04:14 elapsed; 0 hosts completed (2 up), 2 undergoing Connect Scan
Connect Scan Timing: About 95.91% done; ETC: 21:35 (0:00:11 remaining)
Nmap scan report for 10.10.110.2
Host is up.
All 65535 scanned ports on 10.10.110.2 are in ignored states.
Not shown: 65535 filtered tcp ports (no-response)

Nmap scan report for 10.10.110.100
Host is up (0.049s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
65000/tcp open  unknown

Nmap done: 2 IP addresses (2 hosts up) scanned in 263.63 seconds
```

#### 10.10.110.100

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Dante-Prolab]
└─$ sudo nmap -p 21,22,65000 -sCV -A -T4 -O 10.10.110.100 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-30 21:40 CET
Nmap scan report for 10.10.110.100
Host is up (0.057s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Cant get directory listing: PASV IP 172.16.1.100 is not the same as 10.10.110.100
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.8
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 8f:a2:ff:cf:4e:3e:aa:2b:c2:6f:f4:5a:2a:d9:e9:da (RSA)
|   256 07:83:8e:b6:f7:e6:72:e9:65:db:42:fd:ed:d6:93:ee (ECDSA)
|_  256 13:45:c5:ca:db:a6:b4:ae:9c:09:7d:21:cd:9d:74:f4 (ED25519)
65000/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 2 disallowed entries 
|_/wordpress DANTE{Y0u_Cant_G3t_at_m3_br0!}
|_http-title: Apache2 Ubuntu Default Page: It works
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 5.X (88%)
OS CPE: cpe:/o:linux:linux_kernel:5.0
Aggressive OS guesses: Linux 5.0 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   54.88 ms 10.10.14.1
2   55.03 ms 10.10.110.100

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.52 seconds
```