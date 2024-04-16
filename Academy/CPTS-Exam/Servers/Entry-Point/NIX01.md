### ++ Approach 10.129.254.96 ++
#### Credentials
	* joomla:Sup3RS3cuR3@123 (Joomla MySQL)

#### Services
	##### 21 FTP
		Anonymous login allowed
            - Empty file "Uninstaller.lnk"
            - No write permissions

	##### 22 SSH
		-

	##### 25 SMTP
		Telnet flag: 220 WEB-NIX01 ESMTP Postfix (Ubuntu)
        No open relay, need credentials
        With "About us" users and smtp-user-enum.pl script no users found

	##### 53 DNS
		Dig axfr:
            trilocor.local.         86400   IN      NS      trilocor.local.
            trilocor.local.         86400   IN      A       127.0.0.1
            blog.trilocor.local.    86400   IN      A       127.0.0.1
            careers.trilocor.local. 86400   IN      A       127.0.0.1
            dev.trilocor.local.     86400   IN      A       127.0.0.1
            portal.trilocor.local.  86400   IN      A       127.0.0.1
            pr.trilocor.local.      86400   IN      A       127.0.0.1
            remote.trilocor.local.  86400   IN      A       127.0.0.1
            store.trilocor.local.   86400   IN      A       127.0.0.1

	##### 80 Http
		Apache 2.4.41
		Subdomains:
			blog.trilocor.local
				Joomla version 4.1.5 (../administrator/manifests/files/joomla.xml)
				Login page: http://blog.trilocor.local/administrator/index.php
				MySQL credentials: joomla:Sup3RS3cuR3@123 CVE-2023-23752 (https://vulncheck.com/blog/joomla-for-rce)
				Account:  CVE-2023-23752 (https://vulncheck.com/blog/joomla-for-rce)
					"name":"Administrator",
					"username":"Administrator",
					"email":"admin@trilocor.local"

			portal.trilocor.local
				Login to HR tool, no credentials
				Brute force with @hr-smith

			remote.trilocor.local
				Login, no credentials

			dev.trilocor.local
				/transfer -> http://securetransfer-dev.trilocor.local/ (Add to /etc/hosts)

				securetransfer-dev.trilocor.local
					We can create an account test:password123 (test@test.com)
					/download.php
						- fuzzing parameters: file
					/index.php
					/files.php
					/upload.php
					Weird to be here:
						/conn.php
						/storage


			pr.trilocor.local
				User and usernames section, we found @hr-smith what will be useful to bruteforce hr app

			careers.trilocor.local
				Another login

			store.trilocor.local
				More users

	##### 110,995 Pop3
		Need credentials

	##### 111 NFS/rpcbind
		Showmount not showing anything. Message: "clnt_create: RPC: Program not registered"
        Nmap script not showing anything

	##### 143,993 Imap
		Need credentials

	##### 7777 Http
		Werkzeug 2.2.1 / Console - With Pin we should get RCE, but we need directory traversal to read the source code and calculate the pin number (https://hacktricks.boitatech.com.br/pentesting/pentesting-web/werkzeug)

        Python 3.8.10
        Wordpress 5.8.3 (¿?)
		XSS vulnerable (Out of scope) <img src="" onerror=alert(1)>

### ++ Vulnerabilities ++

#### Vuln 1: ++
	* -

### ++ System Interaction ++
#### Foothold  
	* -

#### Privilege Escalation 
	* -

#### Attack chain
	* -
	
#### Post-exploitation 
	* -