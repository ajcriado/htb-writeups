### Nmap

```bash
# Nmap 7.94SVN scan initiated Mon Dec 11 09:46:15 2023 as: nmap -p 22,25,80,110,111,143,443,859,993,995,3306,4190,4445,4559,5038,10000 -sCV -A -T4 -O -oN script-scan 10.129.46.112
Nmap scan report for 10.129.46.112
Host is up (0.036s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp?
|_smtp-commands: Couldnt establish connection on port 25
80/tcp    open  http       Apache httpd 2.2.3
|_http-title: Did not follow redirect to https://10.129.46.112/
|_http-server-header: Apache/2.2.3 (CentOS)
110/tcp   open  pop3?
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            856/udp   status
|_  100024  1            859/tcp   status
143/tcp   open  imap?
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Elastix - Login page
|_ssl-date: 2023-12-11T08:50:50+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_http-server-header: Apache/2.2.3 (CentOS)
859/tcp   open  status     1 (RPC #100024)
993/tcp   open  imaps?
995/tcp   open  pop3s?
3306/tcp  open  mysql?
4190/tcp  open  sieve?
4445/tcp  open  upnotifyp?
4559/tcp  open  hylafax?
5038/tcp  open  asterisk   Asterisk Call Manager 1.1
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesnt have a title (text/html; Charset=iso-8859-1).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.27 - 2.6.28 (95%), Linux 2.6.9 - 2.6.18 (95%), Linux 2.6.9 - 2.6.27 (95%), Sony SMP-N200 media player (95%), ZyXEL o2 HomeBox 6641 router (95%), Linux 2.6.21 (95%), Linux 2.6.18 (95%), Tomato 1.28 (Linux 2.6.22) (95%), Asus RT-AC66U router (Linux 2.6) (95%), Asus RT-N10 router or AXIS 211A Network Camera (Linux 2.6) (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: 127.0.0.1

Host script results:
|_clock-skew: -1s

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   36.49 ms 10.10.14.1
2   36.78 ms 10.129.46.112

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec 11 09:56:01 2023 -- 1 IP address (1 host up) scanned in 585.73 seconds
```