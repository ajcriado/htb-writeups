
#### Nmap

```bash
# Nmap 7.94SVN scan initiated Sat Jan 20 21:13:49 2024 as: /usr/bin/nmap -Pn -sCV -p135,139,445,3128,49666,49667 --open -oN nmap/Script_TCP_192.168.243.189.nmap --system-dns --stats-every 2s 192.168.243.189
Nmap scan report for 192.168.243.189
Host is up (0.68s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3128/tcp  open  http-proxy    Squid http proxy 4.14
|_http-server-header: squid/4.14
|_http-title: ERROR: The requested URL could not be retrieved
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-01-20T20:14:46
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 20 21:15:25 2024 -- 1 IP address (1 host up) scanned in 95.97 seconds
```

#### SPOSE (Squid Pivoting Open Port Scanner)

```bash
# python spose.py --proxy http://192.168.243.189:3128 --target 192.168.243.189
Using proxy address http://192.168.243.189:3128
192.168.243.189 3306 seems OPEN 
192.168.243.189 8080 seems OPEN
```