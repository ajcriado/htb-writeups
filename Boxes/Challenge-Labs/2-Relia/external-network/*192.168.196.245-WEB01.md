### ++ Approach ++
#### Credentials
    * anita (ssh key with passphrase fireball)
    * root
    * offsec
    * miranda
    * steven
    * mark

#### Services
	##### 21 FTP
        Anonymous login allowed
        Nothing here and no write permissions
    
    ##### 80 HTTP
        Path traversal vulnerability found
        Here we can extract anita id_ecdsa key file and crack it with john (fireball passphrase)
    
    ##### 443 HTTPS
        -
    
    ##### 2222 SSH
        -

    ##### 8000 HTTP
        -

### ++ Vulnerabilities ++

#### Vuln 1: Path traversal in webapp in port 80 ++
	* https://www.exploit-db.com/exploits/50383
    * Here we can extract anita id_ecdsa key file

#### Vuln 2: Sudo version 1.8.31 is exploitable ++
	* https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit

### ++ System Interaction ++
#### Foothold  
	* Abusing vuln 1 we get anita key
    * Crack it with ssh2john and john (fireball passphrase) and get ssh shell for anita user

#### Privilege Escalation 
	* We can get root by using the exploit from vuln 2

#### Attack chain
	* Get anita key through Patch traversal, crack it and get a user shell
    * Abuse sudo version 1.8.31 and get root
	
#### Post-exploitation 
	* With /etc/passwd and /etc/shadow we get user hashes