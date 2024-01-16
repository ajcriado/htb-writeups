```bash
┌──(kali㉿kali)-[~/.ssh]
└─$ ssh juno@10.10.11.216                                           
The authenticity of host '10.10.11.216 (10.10.11.216)' can't be established.
ED25519 key fingerprint is SHA256:Ew7jqugz1PCBr4+xKa3GVApxe+GlYwliOFLdMlqXWf8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.216' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Aug 28 03:49:24 PM UTC 2023

  System load:           0.0
  Usage of /:            81.3% of 12.33GB
  Memory usage:          13%
  Swap usage:            0%
  Processes:             246
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.216
  IPv6 address for eth0: dead:beef::250:56ff:feb9:d3aa


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Jun  7 15:13:15 2023 from 10.10.14.23
juno@jupiter:~$ whoami
juno
juno@jupiter:~$ cat user.txt 
9a0972424db469e88d5f3b4d34b417f3
```

Finally we have the user flag. Now lets escalate privileges

Checking processes with netstat we found the following ports open for the machine

```bash
juno@jupiter:~$ netstat -nptl
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State 
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN 
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN 
tcp6       0      0 :::22                   :::*                    LISTEN 
```

Ports 22 and 80 are the ones that we found with nmap, because they are open to outside. Ports 5432, 3000 and 8888 are just open internally. So lets scan the services with nmap and dynamic port forwarding. First connect dynamically with SSH specifying the dynamic port 9050

```bash
┌──(kali㉿kali)-[~]
└─$ ssh -D 9050 juno@10.10.11.216                          
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)
```

Specify the port in /etc/proxychains4.conf adding to the last line this

```plain/text
socks4  127.0.0.1 9050
```

And then scan the ports redirecting the request through proxychains

```bash
┌──(kali㉿kali)-[~]
└─$ proxychains nmap -p 5432,3000,8888 127.0.0.1 -sCV -A -T4
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-28 19:12 CEST

Nmap scan report for localhost (127.0.0.1)
Host is up (0.25s latency).

PORT     STATE SERVICE    VERSION
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: no-store
|     Content-Type: text/html; charset=UTF-8
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 28 Aug 2023 17:12:53 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"/><meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"/><meta name="viewport" content="width=device-width"/><meta name="theme-color" content="#000"/><title>Grafana</title><base href="/"/><link rel="icon" type="image/png" href="public/img/fav32.png"/><link rel="apple-touch-icon" sizes="180x180" href="public/img/apple-touch-icon.png"/><link rel="mask-icon" href="public/img/grafana_mask_icon.svg" color="#F05A28"/><link rel="stylesheet" href="public/build/grafana.dark.922c73a268c5f56fe5fe.css"/><script nonce="">performance.mark('frontend_boot_css_time_seconds');</script><meta name="apple-mobile-web-app-capable" content=
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Cache-Control: no-store
|     Content-Type: text/html; charset=UTF-8
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 28 Aug 2023 17:13:00 GMT
|_    <!doctype html><html lang="en"><head><meta charset="utf-8"/><meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"/><meta name="viewport" content="width=device-width"/><meta name="theme-color" content="#000"/><title>Grafana</title><base href="/"/><link rel="icon" type="image/png" href="public/img/fav32.png"/><link rel="apple-touch-icon" sizes="180x180" href="public/img/apple-touch-icon.png"/><link rel="mask-icon" href="public/img/grafana_mask_icon.svg" color="#F05A28"/><link rel="stylesheet" href="public/build/grafana.dark.922c73a268c5f56fe5fe.css"/><script nonce="">performance.mark('frontend_boot_css_time_seconds');</script><meta name="apple-mobile-web-app-capable" c
5432/tcp open  postgresql PostgreSQL DB 9.6.0 or later
| ssl-cert: Subject: commonName=jupiter
| Subject Alternative Name: DNS:jupiter
| Not valid before: 2023-03-07T10:39:09
|_Not valid after:  2033-03-04T10:39:09
| fingerprint-strings: 
|   SMBProgNeg: 
|     SFATAL
|     VFATAL
|     C0A000
|     Munsupported frontend protocol 65363.19778: server supports 3.0 to 3.0
|     Fpostmaster.c
|     L2139
|_    RProcessStartupPacket
|_ssl-date: TLS randomness does not represent time
8888/tcp open  http       Tornado httpd 6.2
| http-title: Jupyter Notebook
|_Requested resource was /login?next=%2Ftree%3F
| http-robots.txt: 1 disallowed entry 
|_/ 
|_http-server-header: TornadoServer/6.2
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
```

So we have the port 3000 with a service called ppp which returns a 400 bad request, 5432 hosting the postgresql database and 8888 with a webapp called tornado. Lets try the webapp. Forward the service and access from our machine to the website

```bash
┌──(kali㉿kali)-[~]
└─$ ssh -L 8888:127.0.0.1:8888 juno@10.10.11.216
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)
```

Now we can access in our machine in the url http://127.0.0.1:8888/

![[Pasted image 20230828193454.png]]

