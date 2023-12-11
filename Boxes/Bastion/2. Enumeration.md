### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Bastion-10.10.10.134]
└─$ sudo nmap -p 22,135,139,445,5985,47001,49664,49665,49667,49668,49669,49670 -sCV -A -T4 -O 10.10.10.134
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-09 16:20 CET
Nmap scan report for 10.10.10.134
Host is up (0.053s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp   open  msrpc       Microsoft Windows RPC
139/tcp   open  netbios-ssn Microsoft Windows netbios-ssn
445/tcp   open              Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
49664/tcp open  msrpc       Microsoft Windows RPC
49665/tcp open  msrpc       Microsoft Windows RPC
49667/tcp open  msrpc       Microsoft Windows RPC
49668/tcp open  msrpc       Microsoft Windows RPC
49669/tcp open  msrpc       Microsoft Windows RPC
49670/tcp open  msrpc       Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2016 (96%), Microsoft Windows Server 2016 build 10586 - 14393 (95%), Microsoft Windows Server 2012 or Server 2012 R2 (93%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (93%), Microsoft Windows 10 1507 - 1607 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Server 2012 R2 Update 1 (93%), Microsoft Windows Vista SP1 - SP2, Windows Server 2008 SP2, or Windows 7 (93%), Microsoft Windows Server 2012 R2 (93%), Microsoft Windows 10 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-11-09T15:22:01
|_  start_date: 2023-11-09T15:14:52
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-11-09T16:22:01+01:00
|_clock-skew: mean: -19m58s, deviation: 34m35s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   49.63 ms 10.10.14.1
2   50.09 ms 10.10.10.134

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.60 seconds
```