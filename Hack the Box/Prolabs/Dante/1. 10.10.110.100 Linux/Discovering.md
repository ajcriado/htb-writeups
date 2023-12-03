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
- `proxychains4 nmap -p 21,111,135,139,445,1433,2049 -sCV 172.16.1.5`
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
# Nmap 7.94SVN scan initiated Sat Dec  2 09:46:02 2023 as: nmap --min-rate=5000 --open -oN nmap/172.16.1.17-discovery 172.16.1.17
Nmap scan report for 172.16.1.17
Host is up (0.053s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT      STATE SERVICE
80/tcp    open  http
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
10000/tcp open  snet-sensor-mgmt

# Nmap done at Sat Dec  2 09:46:57 2023 -- 1 IP address (1 host up) scanned in 54.87 seconds
```
#### 172.16.1.102

```bash
# Nmap 7.94SVN scan initiated Sat Dec  2 09:47:08 2023 as: nmap --min-rate=5000 --open -oN nmap/172.16.1.102-discovery 172.16.1.102
Nmap scan report for 172.16.1.102
Host is up (0.054s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
443/tcp  open  https
445/tcp  open  microsoft-ds
3306/tcp open  mysql
3389/tcp open  ms-wbt-server

# Nmap done at Sat Dec  2 09:48:03 2023 -- 1 IP address (1 host up) scanned in 54.84 seconds
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