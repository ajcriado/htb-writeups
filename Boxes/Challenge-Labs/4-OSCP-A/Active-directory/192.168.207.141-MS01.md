### ++ Approach 192.168.207.141 ++
#### Credentials
	* administrator:3c4495bbd678fac8c9d218be4f2bbc7b

#### Services
	##### 22 SSH
		- 

	##### 80 Http
		/scripts/GPO.ps1 (Maybe would be useful in a future)

	##### 81 Http
		'Attendance and Payroll System' webapp
		Found 2 exploitdb exploits, we just have to change the endpoint from /apsystem/admin to just /admin

	##### 135 RPC
		No null session

	##### 139,445 SMB
		No null session

	##### 3306 MySQL
		-

	##### 5985,47001 WinRM
		-

### ++ Vulnerabilities ++

#### Vuln 1: SQLi and RCE in 'Attendance and Payroll System' webapp ++
	* We can abuse this vulnerabilities by using **[this exploit](https://www.exploit-db.com/exploits/50801)**
	* Do not forget to change the endpoint from /apsystem/admin to just /admin

### ++ System Interaction ++
#### Foothold as ms01\mary.williams
	* Abuse Vuln 1 and get RCE, so we can get a proper shell through encoded powershell rev shell

#### Privilege Escalation 
	* Abuse SeImpersonatePrivilege

#### Attack chain
	* -
	
#### Post-exploitation 
	* LaZagne:
		Administrator:3c4495bbd678fac8c9d218be4f2bbc7b
		celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd

	* Connections:
		evil-winrm -i 192.168.207.141 -u administrator -H 3c4495bbd678fac8c9d218be4f2bbc7b