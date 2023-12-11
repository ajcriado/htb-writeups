### IP - 10.10.11.230
Linux

### Notes taken

```plain/text
10.10.11.230

Info retrieved:
	kanderson:MRdEQuv6~6P9 (For web app admin panel)
	josh:manchesterunited (SSH)
users:
	app:x:1001:1001::/home/app:/bin/sh
	josh:x:1003:1003::/home/josh:/usr/bin/bash
	postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
	root:x:0:0:root:/root:/bin/bash
	
Ports:
	SSH: 22 Out
	HTTP: 80 Out
	DNS: 53 In
	Tomcat?: 8080 In
	
Interesting files:
	/app/cloudhosting-0.0.1.jar
	/etc/postgresql/14/main/postgresql.conf		nothing
	/etc/nginx/nginx.conf				nothing
	/var/log/nginx/error.log 			denied
	/var/log/nginx/access.log 			denied
	/usr/share/openssh/sshd_config 			binary
	/etc/passwd					nothing
	/usr/local/sbin/laurel				?
	/etc/laurel/config.toml
		# Write log files relative to this directory
		directory = "/var/log/laurel"
		# Drop privileges from root to this user
		user = "_laurel"
		
	/etc/update-motd.d
	/run/motd.dynamic.new
	
Interesting processes:
	root UID=0     PID=1424   | /usr/libexec/upowerd 
	postgres UID=114   PID=1107   | /usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main -c config_file=/etc/postgresql/14/main/postgresql.conf
	app UID=1001  PID=1062   | /usr/bin/java -jar cloudhosting-0.0.1.jar
	root UID=0     PID=849    | /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
	root UID=0     PID=848    | /usr/sbin/irqbalance --foreground
	?	UID=998   PID=772    | /usr/local/sbin/laurel --config /etc/laurel/config.toml
	app UID=1001  PID=34216  | curl localhost:8080/login --request POST --header Content-Type: application/x-www-form-urlencoded --data-raw username=kanderson&password=MRdEQuv6~6P9 -v
	josh UID=1003  PID=34325  | find / -type f -name id_rsa
	josh UID=1003  PID=34466  | /bin/sh /usr/bin/lesspipe
	root UID=0     PID=34661  | /bin/sh /etc/update-motd.d/50-landscape-sysinfo

To do:	
	see postgres file /etc/postgresql/14/main/postgresql.conf
	find / -type f -name id_rsa and find a way to ssh as josh
```