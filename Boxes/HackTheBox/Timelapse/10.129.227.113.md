### ++ Approach 10.129.227.113 ++
#### Credentials
	* test:test (SSH)

#### Services
	##### 53 DNS
		Domain: timelapse.htb
        DC: dc01.timelapse.htb

	##### 135 RPC
		Null session allowed

	##### 139,445 SMB
		Null session allowed
            - Shares folder has a proctected zip file called 

	##### 389 Ldap
		-

	##### 5986 WinRM
		-

### ++ Vulnerabilities ++

#### Vuln 1: SMB with sensitive information exposed ++
	* Null session allowed for SMB where we can find a winrm backup which allow us to get a foothold

### ++ System Interaction ++
#### Foothold  
	- In SMB we have a null session. In Shares folder we can get a zip file called 'winrm_backup.zip' and we crack it with zip2john to get 'supremelegacy' password
    - After decompress the file we find 'legacyy_dev_auth.pfx' which seems a file to authenticate through winrm. Using strings we get the user legacyy@timelapse.htb
    - **[Here](https://notes.shashwatshah.me/windows/active-directory/winrm-using-certificate-pfx)** we find a way to extract the certificates from the pfx file and use it through evil-winrm, but on the first command we get prompted for a password and the previous one doesn't work. After searching some info we found that we can use pfx2john to crack it and get the password 'thuglegacy'
    - Now generate the certificates and connect through evil-winrm:
        openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out private.pem
        openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out cert.crt
        openssl rsa -in private.pem -out private2.pem
        evil-winrm -i 10.129.227.113 -u legacyy -k private2.pem -c cert.crt -S (Here we must use -S to enable SSL)

#### Lateral Movement as svc_deploy
	* With winpeas we found the history file: C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    * In this file we can find svc_deploy password to move laterally, and we can get a shell with evil-winrm enabling SSL:
        evil-winrm -i 10.129.227.113 -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S

#### Privilege Escalation 
    * svc_deploy is a member of LAPS_Readers group, so this user can read the passwords for the Active Directory
    * Commands: 
        Get-ADComputer -Identity 'dc01' -property 'ms-mcs-admpwd'
        evil-winrm -i 10.129.227.113 -u 'administrator' -p 'biwi&0]A4#5j6cT!rY0(yP2g' -S