#### Users

* yoshi:Mushroom! (Admin) (RDP)
* offsec:lab (Post-exploitation)

#### Foothold

* We found yoshi password with password spraying, reusing wario credentials. Yoshi is admin here

#### Privilege Escalation

* Yoshi is admin here

#### Post-exploitation

* Dump offsec credentials with LaZagne

#### Nmap

```bash
# Nmap 7.94SVN scan initiated Wed Jan 31 22:44:38 2024 as: nmap -p 135,139,445,3389,49665,49666,49668,49669 -sCV -A -T4 -O -oN 172.16.216.82/nmap/port-scan.nmap 172.16.216.82
Nmap scan report for 172.16.216.82
Host is up (0.020s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=CLIENT01.medtech.com
| Not valid before: 2024-01-30T18:24:19
|_Not valid after:  2024-07-31T18:24:19
|_ssl-date: 2024-01-31T21:46:17+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: MEDTECH
|   NetBIOS_Domain_Name: MEDTECH
|   NetBIOS_Computer_Name: CLIENT01
|   DNS_Domain_Name: medtech.com
|   DNS_Computer_Name: CLIENT01.medtech.com
|   DNS_Tree_Name: medtech.com
|   Product_Version: 10.0.22000
|_  System_Time: 2024-01-31T21:45:37+00:00
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): IBM z/OS 1.11.X (85%)
OS CPE: cpe:/o:ibm:zos:1.11
Aggressive OS guesses: IBM z/OS 1.11 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-31T21:45:37
|_  start_date: N/A
|_nbstat: NetBIOS name: CLIENT01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:9e:29:99 (VMware)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

TRACEROUTE
HOP RTT      ADDRESS
1   19.82 ms 172.16.216.82

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jan 31 22:46:17 2024 -- 1 IP address (1 host up) scanned in 99.15 seconds
``````