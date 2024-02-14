### ++ Approach ++
#### Credentials
    * adrian:e3cea06e2de8d54d43b84d4b5bffb5b0
    * damon:820d6348890893116880101307197052
    * Administrator:387aef0561b65e4f3cae0960b0fba2d5
    * maildmz@relia.com:DPuBT9tGCBrTbR (creds for SMTP in .189)

#### Services
	##### 80 HTTP
        -

	##### 8000 HTTP
        /CMS/admin.php (Deprecated webapp with admin:admin credentials)
        Through files manager add a webshell with extension .pHp and access it in /cms/media/shell.pHp
    
    ##### 139,445 SMB
        No null session

    ##### 135,49664-69 RPC
        No null session

    ##### 3389 RDP
        -

    ##### 5985,47001 WinRM
        -

### ++ Vulnerabilities ++

#### Vuln 1: Deprecated webapp with weak credentials ++
	* We found in /CMS/admin.php a login page which works with admin:admin credentials
    * https://www.exploit-db.com/exploits/50616

#### Vuln 2: CMS webapp RCE vulnerability ++
	* In admin panel we can get RCE by uploading a php shell with extension .pHp and accessing it through /cms/media/shell.pHp (https://www.exploit-db.com/exploits/50616)

### ++ System Interaction ++
#### Foothold  
	* Abusing vulns 1 and 2

#### Privilege Escalation 
	* Abuse SeImpersonatePrivilege

#### Attack chain
	* Abuse vulns 1 and 2
    * Abuse SeImpersonatePrivilege
	
#### Post-exploitation 
	* Dump hashes
    * As user damon we can extract info in C:\staging folder (.git folder hidden so it's a repository). With git show command we found a deleted file 'email.conf.bak' which provides us with credentials for the email conf of the CMS:
        -Email configuration of the CMS
        -maildmz@relia.com:DPuBT9tGCBrTbR
        -If something breaks contact jim@relia.com as he is responsible for the mail server.
        -Please don't send any office or executable attachments as they get filtered out for security reasons.