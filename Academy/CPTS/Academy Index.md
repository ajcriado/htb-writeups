### Other Modules

* Network Enumeration with Nmap
- Information Gathering - Web Edition
- Shells & Payloads
- Using the Metasploit Framework
# Modules to reference

- #### <u>Footprinting</u>
	- FTP
	- SMB
	- RPC
	- NFS
	- DNS
	- SMTP
	- IMAP
	- POP3
	- SNMP
	- MySQL
	- MSQL
	- IPMI
	- SSH
	- RSync
	- RServices
	- RDP
	- WinRM
	- Oracle TNS
	</br>
- #### <u>Attacking Common Services</u>
	- Attacking FTP 
		- Enumeration, Misconfigurations, Brute Force, FTP Bounce Attack
	- Attacking SMB
		- Enumeration, Misconfigurations, Remote Procedure Call (RPC), Brute Force, Password Spray, Remote Code Execution (RCE)
	- Attacking SQL Databases
		- Enumeration, Misconfigurations, Protocol Specific Attacks, Default Databases, SQL Syntax, Execute Commands, Read/Write Local Files, MSSQL Attacks
	- Attacking RDP
		- Enumeration, Password Spraying, Session Hijacking, Pass the Hash, DisableRestrictedAdmin Registry Key
	- Attacking DNS
		- Enumeration, DNS Zone Transfer, Domain Takeovers and Subdomain Enumeration, DNS Spoofing
	- Attacking Email Services
		- Enumeration, Misconfigurations, Cloud Enumeration, Password Attacks, Protocol Specifics Attacks
	</br>
- #### <u>File Transfers</u> (Ways to move files)
	</br>
- #### <u>Password Attacks</u> (Credential Storage, Brute Forcing, Pass the Hash/Ticket)
	- John the Ripper / Hashcat
	- ##### Credential Storage
		- Linux
			- Files
			- History
			- Memory
			- Key-Rings (Browsers)
			- Passwd, Shadow & Opasswd
		- Windows
			- SAM
			- LSASS
			- Credential Manager / Credential Hunting
				- FindSTR
				- Lazagne
			- Active Directory & NTDS.dit
	- Services
		- WinRM (crackmapexec and evil-winrm)
		- SSH (hydra)
		- RDP (hydra and xfreerdp)
		- SMB (hydra, msfconsole, crackmapexec and smbclient)
	- ##### Password Mutations / Cewl
	- ##### Password Reuse / Default Passwords
	- ##### Pass the Hash
		- NTLM
		- Mimikatz
		- PowerShell Invoke-TheHash
		- Impacket
			- impacket-wmiexec
			- impacket-atexec
			- impacket-smbexec
		- Crackmapexec
		- Evil-winrm
		- RDP
			- Enable Restricted Admin Mode to Allow PtH (If blue screen appears)
	- ##### Pass the Ticket 
		- Pass the Ticket (From Windows, using Mimikatz / Rubeus)
			- Kerberos
			- Pass the Key or OverPass the Hash
			- Pass The Ticket with PowerShell Remoting
		- Pass the Ticket (From Linux)
			- Identifying Linux and Active Directory Integration
			- Finding Kerberos Tickets in Linux
				- Finding Keytab Files
				- Finding ccache Files
				- Abusing KeyTab Files
			- Keytab Extract / Extracting Keytab Hashes with KeyTabExtract
			- Obtaining More Hashes / Abusing Keytab ccache
			- Using Linux Attack Tools with Kerberos
	- Protected Files / Archives
		- Cracking
	- Password Policies

### Pending modules


- Attacking Common Services
- Pivoting, Tunneling, and Port Forwarding
- Active Directory Enumeration & Attacks
- Attacking Web Applications with Ffuf
- Login Brute Forcing
- SQL Injection Fundamentals
- SQLMap Essentials
- Cross-Site Scripting (XSS)
- File Inclusion
- File Upload Attacks
- Command Injections
- Web Attacks
- Attacking Common Applications
- Linux Privilege Escalation
- Windows Privilege Escalation
- Documentation & Reporting
- Attacking Enterprise Networks