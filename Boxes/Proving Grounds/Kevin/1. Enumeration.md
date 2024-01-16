#### Nmap

```bash
# Nmap 7.94SVN scan initiated Mon Jan 15 17:49:50 2024 as: nmap -p 80,135,139,445,3389,3573,49152,49153,49154,49155,49156,49160 -sCV -A -T4 -O -oN nmap/port-scan 192.168.231.45
Nmap scan report for 192.168.231.45
Host is up (0.030s latency).

PORT      STATE SERVICE        VERSION
80/tcp    open  http           GoAhead WebServer
| http-title: HP Power Manager
|_Requested resource was http://192.168.231.45/index.asp
|_http-server-header: GoAhead-Webs
135/tcp   open  msrpc          Microsoft Windows RPC
139/tcp   open  netbios-ssn    Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds   Windows 7 Ultimate N 7600 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server?
3573/tcp  open  tag-ups-1?
49152/tcp open  msrpc          Microsoft Windows RPC
49153/tcp open  msrpc          Microsoft Windows RPC
49154/tcp open  msrpc          Microsoft Windows RPC
49155/tcp open  msrpc          Microsoft Windows RPC
49156/tcp open  msrpc          Microsoft Windows RPC
49160/tcp open  msrpc          Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2008|7|8.1|Vista (89%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_8.1:r1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
Aggressive OS guesses: Microsoft Windows Server 2008 R2 or Windows 8 (89%), Microsoft Windows 7 SP1 (89%), Microsoft Windows 8.1 R1 (89%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 (88%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (88%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (88%), Microsoft Windows Vista SP2 (87%), Microsoft Windows Server 2008 R2 SP1 (87%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: KEVIN; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Ultimate N 7600 (Windows 7 Ultimate N 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::-
|   Computer name: kevin
|   NetBIOS computer name: KEVIN\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-01-15T08:51:18-08:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: KEVIN, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:ba:f9:96 (VMware)
| smb2-time: 
|   date: 2024-01-15T16:51:18
|_  start_date: 2024-01-15T16:46:29
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
|_clock-skew: mean: 2h39m59s, deviation: 4h37m07s, median: 0s

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   27.96 ms 192.168.45.1
2   28.05 ms 192.168.45.254
3   28.31 ms 192.168.251.1
4   28.86 ms 192.168.231.45

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 15 17:51:28 2024 -- 1 IP address (1 host up) scanned in 97.79 seconds
```
```bash
# Nmap 7.94SVN scan initiated Mon Jan 15 17:54:50 2024 as: nmap -p 139,445 --script smb-protocols.nse -oN nmap/smb-protocols 192.168.231.45
Nmap scan report for 192.168.231.45
Host is up (0.041s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2:0:2
|_    2:1:0

# Nmap done at Mon Jan 15 17:54:51 2024 -- 1 IP address (1 host up) scanned in 0.68 seconds
```