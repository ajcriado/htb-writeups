### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Chatterbox-10.10.10.74]
└─$ sudo nmap -p135,139,445,9255,9256,49152,49153,49154,49155,49156,49157 -sCV -A -T4 -O 10.10.10.74
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-07 14:15 CEST
Nmap scan report for 10.10.10.74
Host is up (0.035s latency).

PORT      STATE SERVICE     VERSION
135/tcp   open  msrpc       Microsoft Windows RPC
139/tcp   open  netbios-ssn Microsoft Windows netbios-ssn
445/tcp   open  p}���U      Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  http        AChat chat system httpd
|_http-title: Site doesnt have a title.
|_http-server-header: AChat
9256/tcp  open  achat       AChat chat system
49152/tcp open  msrpc       Microsoft Windows RPC
49153/tcp open  msrpc       Microsoft Windows RPC
49154/tcp open  msrpc       Microsoft Windows RPC
49155/tcp open  msrpc       Microsoft Windows RPC
49156/tcp open  msrpc       Microsoft Windows RPC
49157/tcp open  msrpc       Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 R2 SP1 (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows Vista or Windows 7 SP1 (96%), Microsoft Windows Vista SP1 - SP2, Windows Server 2008 SP2, or Windows 7 (96%), Microsoft Windows Vista SP2, Windows 7, or Windows 7 SP1 (96%), Microsoft Windows Vista SP0 or SP1 (96%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h20m01s, deviation: 2h18m34s, median: 5h00m00s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-09-07T17:16:29
|_  start_date: 2023-09-07T17:11:14
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-09-07T13:16:26-04:00

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   35.28 ms 10.10.14.1
2   35.38 ms 10.10.10.74

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.82 seconds
```