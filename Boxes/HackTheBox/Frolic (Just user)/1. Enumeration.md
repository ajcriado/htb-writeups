### Nmap

```bash
# Nmap 7.94SVN scan initiated Mon Jan  8 08:39:45 2024 as: nmap -p 22,139,445,1880,9999 -sCV -A -T4 -O -oN nmap/port-scan 10.129.22.182
Nmap scan report for forlic.htb (10.129.22.182)
Host is up (0.038s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 87:7b:91:2a:0f:11:b6:57:1e:cb:9f:77:cf:35:e2:21 (RSA)
|   256 b7:9b:06:dd:c2:5e:28:44:78:41:1e:67:7d:1e:b7:62 (ECDSA)
|_  256 21:cf:16:6d:82:a4:30:c3:c6:9c:d7:38:ba:b5:02:b0 (ED25519)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
1880/tcp open  http        Node.js Express framework
9999/tcp open  http        nginx 1.10.3 (Ubuntu)
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.10.3 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (95%), Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.13 or 4.2 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.2 (95%), Linux 4.4 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: FROLIC; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: frolic
|   NetBIOS computer name: FROLIC\x00
|   Domain name: \x00
|   FQDN: frolic
|_  System time: 2024-01-08T13:10:01+05:30
| smb2-time: 
|   date: 2024-01-08T07:40:01
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -1h50m05s, deviation: 3h10m31s, median: -5s
|_nbstat: NetBIOS name: FROLIC, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   37.09 ms 10.10.14.1
2   37.32 ms forlic.htb (10.129.22.182)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan  8 08:41:10 2024 -- 1 IP address (1 host up) scanned in 84.93 seconds
```

### Fuzzing

```bash
# gobuster dir -u http://forlic.htb:9999/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt

/admin                (Status: 301) [Size: 194] [--> http://forlic.htb:9999/admin/]
/test                 (Status: 301) [Size: 194] [--> http://forlic.htb:9999/test/]
/dev                  (Status: 301) [Size: 194] [--> http://forlic.htb:9999/dev/]
/backup               (Status: 301) [Size: 194] [--> http://forlic.htb:9999/backup/]
/loop                 (Status: 301) [Size: 194] [--> http://forlic.htb:9999/loop/]
```
```bash
# for i in dev backup loop test admin; do gobuster dir -u "http://forlic.htb:9999/$i" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t 50; done

	# http://forlic.htb:9999/dev
	/test                 (Status: 200) [Size: 5]
	/backup               (Status: 301) [Size: 194] [--> http://forlic.htb:9999/dev/backup/]
	# http://forlic.htb:9999/backup
	/loop                 (Status: 301) [Size: 194] [--> http://forlic.htb:9999/backup/loop/]
	# http://forlic.htb:9999/loop
	/loop                 (Status: 301) [Size: 194] [--> http://forlic.htb:9999/loop/loop/]
	# http://forlic.htb:9999/test
	# http://forlic.htb:9999/admin
	/css                  (Status: 301) [Size: 194] [--> http://forlic.htb:9999/admin/css/]
	/js                   (Status: 301) [Size: 194] [--> http://forlic.htb:9999/admin/js/]
```
```bash
# Dirsearch started Thu Jan  4 10:16:09 2024 as: /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u http://forlic.htb:1880/

200   150B   http://forlic.htb:1880/auth/login
200    17KB  http://forlic.htb:1880/favicon.ico
401    12B   http://forlic.htb:1880/flow/registries
401    12B   http://forlic.htb:1880/icons
401    12B   http://forlic.htb:1880/nodes
404     0B   http://forlic.htb:1880/projects
401    12B   http://forlic.htb:1880/settings
401    12B   http://forlic.htb:1880/settings/
```