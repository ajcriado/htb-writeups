#### Users

* 

#### Foothold

* 

#### Privilege Escalation

* 

#### Post-exploitation

* 

#### Nmap

```bash
# Nmap 7.94SVN scan initiated Wed Jan 31 21:59:41 2024 as: nmap -p 53,135,139,445,3268,5985,9389,47001,49665,49666,49667,49669,52274,52165,52300 -sCV -A -T4 -O -oN 172.16.216.10/nmap/port-scan.nmap 172.16.216.10
Nmap scan report for 172.16.216.10
Host is up (0.017s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-02 11:06:25Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: medtech.com0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: medtech.com0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
52269/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
52274/tcp open  msrpc         Microsoft Windows RPC
52165/tcp open  msrpc         Microsoft Windows RPC
52300/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): IBM z/OS 2.1.X (85%)
OS CPE: cpe:/o:ibm:zos:2.1
Aggressive OS guesses: IBM z/OS 2.1 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-31T21:00:41
|_  start_date: N/A
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:9e:32:3a (VMware)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE
HOP RTT      ADDRESS
1   16.80 ms 172.16.216.10

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jan 31 22:01:21 2024 -- 1 IP address (1 host up) scanned in 99.86 seconds
```