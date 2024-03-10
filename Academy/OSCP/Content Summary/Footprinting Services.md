
> [!info] Always run a first scan with my script of **[Autonmap:](https://github.com/ajcriado/burbles-by-peluqqi/blob/main/autonmap)** `autonmap -H 192.168.235.137 -t script`

## Host-based Enumeration

##### **[FTP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp)** (TCP 20, 21)

> **Note: ** If combined with Http, check to upload a file and execute it in the Http service

|**Command**|**Description**|
|-|-|
| `nmap --script ftp-* -p 21 <ip>` | Nmap port scan |
| `ftp <FQDN/IP>` | Interact with the FTP service on the target. |
| `nc -nv <FQDN/IP> 21` | Interact with the FTP service on the target. |
| `telnet <FQDN/IP> 21` | Interact with the FTP service on the target. |
| `openssl s_client -connect <FQDN/IP>:21 -starttls ftp` | Interact with the FTP service on the target using encrypted connection. |
| `wget -m ftp://anonymous:anonymous@<target>:<port>` | Download all available files on the target FTP server. |
| `wget -m --no-passive ftp://anonymous:anonymous@<target>:<port>` | Download all available files on the target FTP server (no passive) |
| `passive mode` | If a firewall protects the client, the server cannot reply because all external connections are blocked. For this purpose, the `passive mode` has been developed. Here, the server announces a port through which the client can establish the data channel. |
##### **[SMB](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb)** (TCP 137, 138, 139, 445)

> **Note: ** If combined with Http, check to upload a file and execute it in the Http service

|**Command**|**Description**|
|-|-|
| `smbclient -N -L //<FQDN/IP>` | Null session authentication on SMB. |
| `smbclient //<FQDN/IP>/<share>` | Connect to a specific SMB share. |
| `rpcclient -U "" <FQDN/IP>` | Interaction with the target using RPC. |
| `samrdump.py <FQDN/IP>` | Username enumeration using Impacket scripts. |
| `smbmap -H <FQDN/IP>` | Enumerating SMB shares. |
| `crackmapexec smb <FQDN/IP> --shares -u '' -p ''` | Enumerating SMB shares using null session authentication. |
| `enum4linux-ng.py <FQDN/IP> -A` | **SMB enumeration using enum4linux.** |
|`smb: \> tarmode`<br>`smb: \> recurse`<br>`smb: \> prompt`<br>`smb: \> mget *`|Download all files in smbclient|

|**RPCClient**|**Description**|
|-|-|
|`srvinfo`|Server information.|
|`enumdomains`|Enumerate all domains that are deployed in the network.|
|`querydominfo`|Provides domain, server, and user information of deployed domains.|
|`netshareenumall`|Enumerates all available shares.|
|`netsharegetinfo <share>`|Provides information about a specific share.|
|`enumdomusers`|Enumerates all domain users.|
|`queryuser <RID>`|Provides information about a specific user.|

```bash
#### Brute Forcing User RIDs
for i in $(seq 500 1100);do rpcclient -N -U "" <IP> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```
##### **[NFS](https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting)** (TCP 111, 2049)
|**Command**|**Description**|
|-|-|
| `showmount -e <FQDN/IP>` | Show available NFS shares. |
| `mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock` | Mount the specific NFS share.umount ./target-NFS |
| `umount ./target-NFS` | Unmount the specific NFS share. |
| `/etc/exports` | Config file  |
| `sudo nmap --script nfs* <IP> -sV -p111,2049` | Script scan default ports  |

##### **[DNS](https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns)** (TCP 53)
|**Command**|**Description**|
|-|-|
| `dig ns <domain.tld> @<nameserver>` | NS request to the specific nameserver. |
| `dig any <domain.tld> @<nameserver>` | ANY request to the specific nameserver. |
| `dig axfr <domain.tld> @<nameserver>` | AXFR request to the specific nameserver. |
| `dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f /.../subdomains-top1million-110000.txt <domain.tld>` | Subdomain brute forcing. |


##### **[SMTP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp)** (TCP 25, 465, 587)

**[Script](https://github.com/captain-noob/username-wordlist-generator)** to create a list of users by name
/usr/share/seclists/Usernames/Names/names.txt More users

**[Script](https://github.com/pentestmonkey/smtp-user-enum/blob/master/smtp-user-enum.pl)** to enum users of the previous wordlists:
	`perl smtp-user-enum.pl -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 192.168.235.137`

|**Command**|**Description**|
|-|-|
| `telnet <FQDN/IP> 25` |  |
| `sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v` |Open relay|
| `nmap 10.129.205.171 -p25 --script smtp-enum-users.nse` |Enum users|

|**Command**|**Description**|
|---|---|
|`AUTH LOGIN`|Used to authenticate the client, then it will ask you for username and password in base64|
|`HELO`|The client logs in with its computer name and thus starts the session.|
|`MAIL FROM`|The client names the email sender.|
|`RCPT TO`|The client names the email recipient.|
|`DATA`|The client initiates the transmission of the email.|
|`RSET`|The client aborts the initiated transmission but keeps the connection between client and server.|
|`VRFY`|The client checks if a mailbox is available for message transfer.|
|`EXPN`|The client also checks if a mailbox is available for messaging with this command.|
|`NOOP`|The client requests a response from the server to prevent disconnection due to time-out.|
|`QUIT`|The client terminates the session.|

##### **[IMAP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-imap)** (TCP 143, 993) /**[POP3](https://book.hacktricks.xyz/network-services-pentesting/pentesting-pop)** (TCP 110, 995)
|**Command**|**Description**|
|-|-|
| `curl -k 'imaps://<FQDN/IP>' --user <user>:<password>` | Log in to the IMAPS service using cURL. |
| `openssl s_client -connect <FQDN/IP>:imaps` | Connect to the IMAPS service. |
| `telnet <IP> 143` | Connect to the IMAPS service. (2) |
| `openssl s_client -connect <FQDN/IP>:pop3s` | Connect to the POP3s service. |
| `telnet <IP> 110` | Connect to the POP3s service. (2) |

|**IMAP Command**|**Description**|
|---|---|
|`1 LOGIN username password`|User's login.|
|`1 LIST "" *`<br/>`1 SELECT INBOX`<br/>`1 FETCH 1 BODY[HEADER]`<br/>`1 FETCH 1 BODY[TEXT]`|List folders, select one and retrieve 1 message|
|`1 LIST "" *`|Lists all directories.|
|`1 CREATE "INBOX"`|Creates a mailbox with a specified name.|
|`1 DELETE "INBOX"`|Deletes a mailbox.|
|`1 RENAME "ToRead" "Important"`|Renames a mailbox.|
|`1 LSUB "" *`|Returns a subset of names from the set of names that the User has declared as being `active` or `subscribed`.|
|`1 SELECT INBOX`|Selects a mailbox so that messages in the mailbox can be accessed.|
|`1 UNSELECT INBOX`|Exits the selected mailbox.|
|`1 FETCH <ID> all`|Retrieves data associated with a message in the mailbox.|
|`1 CLOSE`|Removes all messages with the `Deleted` flag set.|
|`1 LOGOUT`|Closes the connection with the IMAP server.|

|**POP3 Command**|**Description**|
|---|---|
|`USER username`|Identifies the user.|
|`PASS password`|Authentication of the user using its password.|
|`LIST`<br/>`RETR 1`|List messages and retrieve the first one|
|`STAT`|Requests the number of saved emails from the server.|
|`LIST`|Requests from the server the number and size of all emails.|
|`RETR id`|Requests the server to deliver the requested email by ID.|
|`DELE id`|Requests the server to delete the requested email by ID.|
|`CAPA`|Requests the server to display the server capabilities.|
|`RSET`|Requests the server to reset the transmitted information.|
|`QUIT`|Closes the connection with the POP3 server.|

##### **[SNMP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)** (TCP 161, 162 - UDP 10161, 10162)
| **Command**                                                           | **Description**                                     |
| --------------------------------------------------------------------- | --------------------------------------------------- |
| `onesixtyone -c /.../Discovery/SNMP/snmp.txt <FQDN/IP>`               | Bruteforcing community strings of the SNMP service. |
| `snmpwalk -v2c -c <found community> <FQDN/IP>`                        | Querying OIDs using snmpwalk.                       |
| `braa <community string>@<FQDN/IP>:.1.*`                              | Bruteforcing SNMP service OIDs.                     |
| `snmpwalk -v 1 -c public <IP> 'NET-SNMP-EXTEND-MIB::nsExtendObjects'` |                                                     |


##### **[MySQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql)** (TCP 3306)
| **Command**                                     | **Description**            |
| ----------------------------------------------- | -------------------------- |
| `mysql -u <user> -p<password> -h <FQDN/IP>`     | Login to the MySQL server. |
| `sudo nmap <IP> -sV -sC -p3306 --script mysql*` | Nmap script scan           |

|**Command**|**Description**|
|---|---|
|`mysql -u <user> -p<password> -h <IP address>`|Connect to the MySQL server. There should **not** be a space between the '-p' flag, and the password.|
|`show databases;`|Show all databases.|
|`use <database>;`|Select one of the existing databases.|
|`show tables;`|Show all available tables in the selected database.|
|`show columns from <table>;`|Show all columns in the selected database.|
|`select * from <table>;`|Show everything in the desired table.|
|`select * from <table> where <column> = "<string>";`|Search for needed `string` in the desired table.|
##### **[MSSQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)** (TCP 1433)
| **Command** | **Description** |
| ---- | ---- |
| `sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>` | Nmap port scan |
| `mssqlclient.py <user>@<FQDN/IP> -windows-auth` | Log in to the MSSQL server using Windows authentication. |
| `SQL> select name from sys.databases` | Select databases in mssqlclient |
| `SQL> SELECT * FROM fn_my_permissions(NULL, 'SERVER');` | Check user permissions in mssqlclient |
| `SQL> SELECT SYSTEM_USER`<br>`SQL> SELECT IS_SRVROLEMEMBER('sysadmin')` | Retrieve system user in mssqlclient |
| `SQL> EXECUTE AS LOGIN = 'sa'` | Execute as user in mssqlclient (if user has permission) |
| `SQL> EXECUTE sp_configure 'show advanced options', 1`<br>`SQL> RECONFIGURE`<br>`SQL> EXECUTE sp_configure 'xp_cmdshell', 1`<br>`SQL> RECONFIGURE` | Enable xp_cmdshell in mssqlclient (if user has permission) |
| `SQL> xp_cmdshell 'whoami'` | Execute command in mssqlclient |


##### **[IPMI](https://book.hacktricks.xyz/network-services-pentesting/623-udp-ipmi)** (TCP/UDP 623)
|**Command**|**Description**|
|-|-|
| `sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local` | Nmap port scan |
| `msf6 auxiliary(scanner/ipmi/ipmi_version)` | IPMI version detection. |
| `msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)` | Dump IPMI hashes. |


##### Linux Remote Management (**[SSH](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh)** TCP 22 - **[Rsync](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync)** TCP 873 - R-Services 512, 513, 514 )
|**Command**|**Description**|
|-|-|
| `ssh-audit.py <FQDN/IP>` | Remote security audit against the target SSH service. |
| `ssh <user>@<FQDN/IP>` | Log in to the SSH server using the SSH client. |
| `ssh -i private.key <user>@<FQDN/IP>` | Log in to the SSH server using private key. |
| `ssh <user>@<FQDN/IP> -o PreferredAuthentications=password` | Enforce password-based authentication. |
| `sudo nmap -sV -p 873 127.0.0.1` | Rsync port scan |
| `nc -nv 127.0.0.1 873 `<br/> `#list` | Probing for Accessible Shares |
| `rsync -av --list-only rsync://127.0.0.1/dev` | Enumerating an open share |
| `rsync -av rsync://127.0.0.1/dev` | Sync all files to our attack host |
| `rsync -av rsync://127.0.0.1/dev -e "ssh -p2222"` | Sync all files to our attack host if ssh is configured in a non-standard port |
The [R-commands](https://en.wikipedia.org/wiki/Berkeley_r-commands) suite consists of the following programs:
- rcp (`remote copy`)
- rexec (`remote execution`)
- rlogin (`remote login`)
- rsh (`remote shell`)
- rstat
- ruptime
- rwho (`remote who`)

|**Command**|**Service Daemon**|**Port**|**Transport Protocol**|**Description**|
|---|---|---|---|---|
|`rcp`|`rshd`|514|TCP|Copy a file or directory bidirectionally from the local system to the remote system (or vice versa) or from one remote system to another. It works like the `cp` command on Linux but provides `no warning to the user for overwriting existing files on a system`.|
|`rsh`|`rshd`|514|TCP|Opens a shell on a remote machine without a login procedure. Relies upon the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files for validation.|
|`rexec`|`rexecd`|512|TCP|Enables a user to run shell commands on a remote machine. Requires authentication through the use of a `username` and `password` through an unencrypted network socket. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.|
|`rlogin`|`rlogind`|513|TCP|Enables a user to log in to a remote host over the network. It works similarly to `telnet` but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.|

**~/.ssh/authorized_keys**
During a pentest or audit, you might want to add an authorized_keys file to let you log in using an SSH key. The authorized_keys file lives in a user’s home directory on the SSH server.  It holds the public keys of the users allowed to log into that user’s account. 
* Generate a public/private key pair like this: `ssh-keygen -f mykey`
* Change the name of `mykey.pub` to `authorized_keys` and move the file to the server

If you want to shortest possible key (because your arbitrary-file-write vector is limited), do this:
* `ssh-keygen -f mykey -t rsa -b 768`

Connect to the target system like this (you need to know the username of the user you added an authorized key for):
* `ssh -i mykey user@10.0.0.1`

Caveat: The authorized_keys file might not work if it’s writable by other users.  If you already have shell access you can `chmod 600 ~/.ssh/authorized_keys`.  However, if you’re remotely exploiting an arbitrary file-write vulnerability and happen to have a weak umask, you may have problems.
##### Windows Remote Management (**[RDP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp)** TCP 3389 - **[WinRM](https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm)** TCP 5985, 5986, ¿47001?)
|**Command**|**Description**|
|-|-|
| `nmap -sV -sC 10.129.201.248 -p3389 --script rdp*` | Nmap port scan for RDP |
| `rdp-sec-check.pl <FQDN/IP>` | Check the security settings of the RDP service. |
| `xfreerdp /u:<user> /p:"<password>" /v:<FQDN/IP>` | Log in to the RDP server from Linux. |
| `nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n*` | Nmap port scan for WinRM |
| `evil-winrm -i <FQDN/IP> -u <user> -p <password>` | Log in to the WinRM server. |
| `wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>"` | Execute command using the WMI service. |

##### **[Oracle TNS](https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener)** (TCP 1521, 1522-1529)
|**Command**|**Description**|
|-|-|
| `sudo nmap -p1521 -sV 10.129.204.235 --open` | Nmap port scanning |
| `sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute` | Nmap SID bruteforcing |
| `sudo odat all -s <FQDN/IP> --output-file scripts/odat-enumeration` | Perform a variety of scans to gather information about the Oracle database services and its components. |
| `sqlplus <user>/<pass>@<FQDN/IP>/<db>` | Log in to the Oracle database. |
| `select table_name from all_tables;` | SQLPlus: query all tables |
| `/opt/odat/odat.py utlfile -s 10.129.36.208 -p 1521 -d XE -U SCOTT -P tiger --sysdba --putFile C:\\inetpub\\wwwroot shell.aspx cmdasp.aspx`<br/>`go to http://10.129.36.208/shell.aspx` | Upload a webshell. |
