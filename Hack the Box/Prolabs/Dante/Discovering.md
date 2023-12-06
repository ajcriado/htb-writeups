### Initial Discovery
```bash
┌──(kali㉿kali)-[/Shared/htb-writeups]
└─$ for i in $(seq 254); do ping 10.10.110.$i -c1 -W1 & done | grep from 
64 bytes from 10.10.110.2: icmp_seq=1 ttl=64 time=55.6 ms
64 bytes from 10.10.110.100: icmp_seq=1 ttl=62 time=76.4 ms
```

#### Nmap

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
### Discovery from 10.10.110.100
#### Ping sweep

```bash
root@DANTE-WEB-NIX01:~# for i in $(seq 254); do ping 172.16.1.$i -c1 -W1 & done | grep from
64 bytes from 172.16.1.10: icmp_seq=1 ttl=64 time=0.223 ms
64 bytes from 172.16.1.5: icmp_seq=1 ttl=128 time=0.376 ms
64 bytes from 172.16.1.13: icmp_seq=1 ttl=128 time=0.418 ms
64 bytes from 172.16.1.12: icmp_seq=1 ttl=64 time=0.218 ms
64 bytes from 172.16.1.17: icmp_seq=1 ttl=64 time=0.211 ms
64 bytes from 172.16.1.100: icmp_seq=1 ttl=64 time=0.020 ms
64 bytes from 172.16.1.102: icmp_seq=1 ttl=128 time=0.247 ms
64 bytes from 172.16.1.19: icmp_seq=1 ttl=64 time=0.171 ms
64 bytes from 172.16.1.20: icmp_seq=1 ttl=128 time=0.615 ms
64 bytes from 172.16.1.101: icmp_seq=1 ttl=128 time=0.422 ms
```

#### Scope

```text
172.16.1.10
172.16.1.5
172.16.1.13
172.16.1.12
172.16.1.17
172.16.1.100
172.16.1.102
172.16.1.19
172.16.1.20
172.16.1.101
```

<u>Command execute for port discovery</u>:
- `proxychains4 nmap --min-rate=5000 --open IP -oN nmap/IP-discovery`
- `proxychains4 nmap -p 21,111,135,139,445,1433,2049 -A -T4 172.16.1.5`
#### 172.16.1.10

```bash
# Nmap 7.94SVN scan initiated Fri Dec  1 22:45:57 2023 as: nmap -p- -A -T4 -oN nmap/172.16.1.10-discovery 172.16.1.10
Nmap scan report for 172.16.1.10
Host is up (0.051s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 5a:9c:1b:a5:c1:7f:2d:4f:4b:e8:cc:7b:e4:47:bc:a9 (RSA)
|   256 fd:d6:3a:3f:a8:04:56:4c:e2:76:db:85:91:0c:5e:42 (ECDSA)
|_  256 e2:d5:17:7c:58:75:26:5b:e1:1b:98:39:3b:2c:6c:fc (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Dante Hosting
|_http-server-header: Apache/2.4.41 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2023-12-01T22:43:49
|_  start_date: N/A
|_clock-skew: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Dec  1 23:43:56 2023 -- 1 IP address (1 host up) scanned in 3479.20 seconds
```
#### 172.16.1.5

```bash
# Nmap 7.94SVN scan initiated Sat Dec  2 09:35:02 2023 as: nmap --min-rate=5000 --open -oN nmap/172.16.1.5-discovery 172.16.1.5
Nmap scan report for 172.16.1.5
Host is up (0.054s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT     STATE SERVICE
21/tcp   open  ftp
111/tcp  open  rpcbind
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
2049/tcp open  nfs

# Nmap done at Sat Dec  2 09:35:59 2023 -- 1 IP address (1 host up) scanned in 57.41 seconds
```
#### 172.16.1.13

Really slow host, I check open ports by looking proxychains log. Basically we have website in http (80) and https (443), and smb

```bash
┌──(kali㉿kali)-[~/…/Boxes/Dante-Prolab/10.10.110.100/172.16.1.13]
└─$ proxychains nmap -A -T4 172.16.1.13   
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-04 23:48 CET
[proxychains] Strict chain  ...  127.0.0.1:8081  ...  172.16.1.13:80  ...  OK
[...SNIP...]
[proxychains] Strict chain  ...  127.0.0.1:8081  ...  172.16.1.13:443  ...  OK
[...SNIP...]
[proxychains] Strict chain  ...  127.0.0.1:8081  ...  172.16.1.13:445  ...  OK
[...SNIP...]
```

#### 172.16.1.12

```bash
# Nmap 7.94SVN scan initiated Sat Dec  2 09:44:51 2023 as: nmap -p 21,22,80,443,3306 -sCV 172.16.1.12
Nmap scan report for 172.16.1.12
Host is up (0.13s latency).

PORT     STATE SERVICE  VERSION
21/tcp   open  ftp?
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (ProFTPD) [::ffff:172.16.1.12]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp   open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 22:cc:a3:e8:7d:d5:65:6d:9d:ea:17:d1:d9:1b:32:cb (RSA)
|   256 04:fb:b6:1a:db:95:46:b7:22:13:61:24:76:80:1e:b8 (ECDSA)
|_  256 ae:c4:55:67:6e:be:ba:65:54:a3:c3:fc:08:29:24:0e (ED25519)
80/tcp   open  http     Apache httpd 2.4.43 ((Unix) OpenSSL/1.1.1g PHP/7.4.7 mod_perl/2.0.11 Perl/v5.30.3)
|_http-server-header: Apache/2.4.43 (Unix) OpenSSL/1.1.1g PHP/7.4.7 mod_perl/2.0.11 Perl/v5.30.3
| http-title: Welcome to XAMPP
|_Requested resource was http://172.16.1.12/dashboard/
443/tcp  open  ssl/http Apache httpd 2.4.43 ((Unix) OpenSSL/1.1.1g PHP/7.4.7 mod_perl/2.0.11 Perl/v5.30.3)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.43 (Unix) OpenSSL/1.1.1g PHP/7.4.7 mod_perl/2.0.11 Perl/v5.30.3
|_http-title: Bad request!
| ssl-cert: Subject: commonName=localhost/organizationName=Apache Friends/stateOrProvinceName=Berlin/countryName=DE
| Not valid before: 2004-10-01T09:10:30
|_Not valid after:  2010-09-30T09:10:30
3306/tcp open  mysql?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, NULL, RPCCheck, RTSPRequest, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 
|_    Host '172.16.1.100' is not allowed to connect to this MariaDB server
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
[...SNIP...]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 225.27 seconds
```
#### 172.16.1.17

```bash
# Nmap 7.94SVN scan initiated Sat Dec  2 09:46:02 2023 as: nmap -p 80,139,445,10000 -A -T4 172.16.1.17
Nmap scan report for 172.16.1.17
Host is up (0.14s latency).

PORT      STATE SERVICE     VERSION
80/tcp    open  http        Apache httpd 2.4.41
|_http-title: Index of /
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 37M   2020-06-25 13:00  webmin-1.900.zip
| -     2020-07-13 02:21  webmin/
|_
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
10000/tcp open  http        MiniServ 1.900 (Webmin httpd)
|_http-title: Login to Webmin
|_http-server-header: MiniServ/1.900
| http-robots.txt: 1 disallowed entry 
|_/
Service Info: Host: 127.0.0.1

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-12-03T16:25:21
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.41 seconds
```
#### 172.16.1.102

```bash
# Nmap 7.94SVN scan initiated Wed Dec  6 08:51:09 2023 as: nmap -A -T4 -oN port-discovery 172.16.1.102
Nmap scan report for 172.16.1.102
Host is up (0.053s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/7.4.0)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.0
|_http-title: Dante Marriage Registration System :: Home Page
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/7.4.0)
| tls-alpn: 
|   h2
|_  http/1.1
|_http-title: Dante Marriage Registration System :: Home Page
| ssl-cert: Subject: commonName=localhost/organizationName=TESTING CERTIFICATE
| Subject Alternative Name: DNS:localhost
| Not valid before: 2022-06-24T01:07:25
|_Not valid after:  2022-12-24T01:07:25
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.0
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
3306/tcp open  mysql         MySQL (unauthorized)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-12-06T07:52:35+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DANTE-WS03
| Not valid before: 2023-12-05T03:13:10
|_Not valid after:  2024-06-05T03:13:10
| rdp-ntlm-info: 
|   Target_Name: DANTE-WS03
|   NetBIOS_Domain_Name: DANTE-WS03
|   NetBIOS_Computer_Name: DANTE-WS03
|   DNS_Domain_Name: DANTE-WS03
|   DNS_Computer_Name: DANTE-WS03
|   Product_Version: 10.0.19041
|_  System_Time: 2023-12-06T07:52:23+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-12-06T07:52:23
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec  6 08:52:36 2023 -- 1 IP address (1 host up) scanned in 87.29 seconds

```
#### 172.16.1.19

```bash
# Nmap 7.94SVN scan initiated Sat Dec  2 09:49:48 2023 as: nmap --min-rate=5000 --open -oN nmap/172.16.1.19-discovery 172.16.1.19
Nmap scan report for 172.16.1.19
Host is up (0.054s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE
80/tcp   open  http
8080/tcp open  http-proxy

# Nmap done at Sat Dec  2 09:50:43 2023 -- 1 IP address (1 host up) scanned in 55.76 seconds
```
#### 172.16.1.20

```bash
# Nmap 7.94SVN scan initiated Sat Dec  2 09:53:41 2023 as: nmap --min-rate=5000 --open -oN nmap/172.16.1.20-discovery 172.16.1.20
Nmap scan report for 172.16.1.20
Host is up (0.055s latency).
Not shown: 978 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49159/tcp open  unknown

# Nmap done at Sat Dec  2 09:54:36 2023 -- 1 IP address (1 host up) scanned in 55.32 seconds
```
#### 172.16.1.101

```bash
# Nmap 7.94SVN scan initiated Sat Dec  2 10:24:54 2023 as: nmap --min-rate=5000 --open -oN nmap/172.16.1.101-discovery 172.16.1.101
Nmap scan report for 172.16.1.101
Host is up (0.060s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE
21/tcp  open  ftp
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

# Nmap done at Sat Dec  2 10:25:51 2023 -- 1 IP address (1 host up) scanned in 57.32 seconds
```