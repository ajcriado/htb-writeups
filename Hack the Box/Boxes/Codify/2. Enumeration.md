### Nmap

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p 22,80,3000,8080,8081 -sCV -A -T4 -O 10.10.11.239
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-05 14:24 CET
Nmap scan report for 10.10.11.239
Host is up (0.047s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http       Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://codify.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http       Node.js Express framework
|_http-title: Codify
8080/tcp open  http-proxy
|_http-title: Site doesnt have a title (text/html).
|_http-open-proxy: Proxy might be redirecting requests
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, SMBProgNeg, SSLSessionReq, Socks4, Socks5, TLSSessionReq, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: text/html
|     Date: Sun, 05 Nov 2023 13:24:59 GMT
|     Connection: close
|     Hello World!
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: text/html
|     Date: Sun, 05 Nov 2023 13:24:58 GMT
|     Connection: close
|_    Hello World!
8081/tcp open  http       SimpleHTTPServer 0.6 (Python 3.10.12)
|_http-title: Directory listing for /
|_http-server-header: SimpleHTTP/0.6 Python/3.10.12
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94%I=7%D=11/5%Time=654797AB%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,70,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/html\r\nDa
SF:te:\x20Sun,\x2005\x20Nov\x202023\x2013:24:58\x20GMT\r\nConnection:\x20c
SF:lose\r\n\r\nHello\x20World!")%r(HTTPOptions,70,"HTTP/1\.1\x20200\x20OK\
SF:r\nContent-Type:\x20text/html\r\nDate:\x20Sun,\x2005\x20Nov\x202023\x20
SF:13:24:58\x20GMT\r\nConnection:\x20close\r\n\r\nHello\x20World!")%r(RTSP
SF:Request,70,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/html\r\nDat
SF:e:\x20Sun,\x2005\x20Nov\x202023\x2013:24:58\x20GMT\r\nConnection:\x20cl
SF:ose\r\n\r\nHello\x20World!")%r(FourOhFourRequest,70,"HTTP/1\.1\x20200\x
SF:20OK\r\nContent-Type:\x20text/html\r\nDate:\x20Sun,\x2005\x20Nov\x20202
SF:3\x2013:24:59\x20GMT\r\nConnection:\x20close\r\n\r\nHello\x20World!")%r
SF:(Socks5,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\
SF:r\n\r\n")%r(Socks4,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection
SF::\x20close\r\n\r\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,"HTTP/1\.1\
SF:x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSStatusR
SF:equestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20clos
SF:e\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection
SF::\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,2F,"HTTP/
SF:1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(TLSSe
SF:ssionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close
SF:\r\n\r\n")%r(Kerberos,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnect
SF:ion:\x20close\r\n\r\n")%r(SMBProgNeg,2F,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nConnection:\x20close\r\n\r\n")%r(X11Probe,2F,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(LPDString,2F,"HTT
SF:P/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(LDA
SF:PSearchReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20clo
SF:se\r\n\r\n")%r(LDAPBindReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:nnection:\x20close\r\n\r\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   45.49 ms 10.10.14.1
2   45.54 ms 10.10.11.239

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.09 seconds
```

### Fuzzing

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://codify.htb/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/codify.htb/-_23-11-06_12-54-46.txt

Error Log: /home/kali/.dirsearch/logs/errors-23-11-06_12-54-46.log

Target: http://codify.htb/

[12:54:47] Starting: 
[12:54:52] 200 -    3KB - /About                                            
[12:54:55] 200 -    3KB - /about                                            
[12:55:09] 200 -    3KB - /editor/                                          
[12:55:09] 200 -    3KB - /editor                                           
[12:55:24] 403 -  275B  - /server-status/                                   
[12:55:24] 403 -  275B  - /server-status                                    
                                                                             
Task Completed
```