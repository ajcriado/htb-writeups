### Domain


### Nmap

```bash
┌─[htb-student@skills-foothold]─[/root/.msf4]
└──╼ $nmap -p 80,135,139,445 -sVC 172.16.1.13
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-18 06:20 EDT
Nmap scan report for 172.16.1.13
Host is up (0.0048s latency).

PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: 172.16.1.13 - /
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 2h20m00s, deviation: 4h02m29s, median: 0s
|_nbstat: NetBIOS name: SHELLS-WINBLUE, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:10:11 (VMware)
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: SHELLS-WINBLUE
|   NetBIOS computer name: SHELLS-WINBLUE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-07-18T03:20:25-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-07-18T10:20:25
|_  start_date: 2023-07-18T09:48:07

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.31 seconds
```