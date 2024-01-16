#### Nmap

```bash
# Nmap 7.94SVN scan initiated Mon Jan  1 19:21:07 2024 as: nmap -p 135,5985,8080,29817,29819,29820 -sCV -A -T4 -O -oN nmap/port-scan -Pn 10.129.2.27
Nmap scan report for 10.129.2.27
Host is up (0.047s latency).

PORT      STATE SERVICE  VERSION
135/tcp   open  msrpc    Microsoft Windows RPC
5985/tcp  open  upnp     Microsoft IIS httpd
8080/tcp  open  upnp     Microsoft IIS httpd
|_http-title: Site doesnt have a title.
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Windows Device Portal
|_http-server-header: Microsoft-HTTPAPI/2.0
29817/tcp open  unknown
29819/tcp open  arcserve ARCserve Discovery
29820/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port29820-TCP:V=7.94SVN%I=7%D=1/1%Time=6593029A%P=x86_64-pc-linux-gnu%r
SF:(NULL,10,"\*LY\xa5\xfb`\x04G\xa9m\x1c\xc9}\xc8O\x12")%r(GenericLines,10
SF:,"\*LY\xa5\xfb`\x04G\xa9m\x1c\xc9}\xc8O\x12")%r(Help,10,"\*LY\xa5\xfb`\
SF:x04G\xa9m\x1c\xc9}\xc8O\x12")%r(JavaRMI,10,"\*LY\xa5\xfb`\x04G\xa9m\x1c
SF:\xc9}\xc8O\x12");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: PING; OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 29820/tcp)
HOP RTT      ADDRESS
1   42.37 ms 10.10.14.1
2   42.63 ms 10.129.2.27

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan  1 19:22:25 2024 -- 1 IP address (1 host up) scanned in 77.87 seconds
```