### Nmap

```bash
# Nmap 7.94SVN scan initiated Wed Dec 27 08:40:31 2023 as: nmap -p 22,80,111,6697,8067,65534 -sCV -A -T4 -O -oN nmap/port-scan 10.129.34.15
Nmap scan report for 10.129.34.15
Host is up (0.052s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 6a:5d:f5:bd:cf:83:78:b6:75:31:9b:dc:79:c5:fd:ad (DSA)
|   2048 75:2e:66:bf:b9:3c:cc:f7:7e:84:8a:8b:f0:81:02:33 (RSA)
|   256 c8:a3:a2:5e:34:9a:c4:9b:90:53:f7:50:bf:ea:25:3b (ECDSA)
|_  256 8d:1b:43:c7:d0:1a:4c:05:cf:82:ed:c1:01:63:a2:0c (ED25519)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Site doesnt have a title (text/html).
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          32828/tcp   status
|   100024  1          33381/udp6  status
|   100024  1          36515/tcp6  status
|_  100024  1          48607/udp   status
6697/tcp  open  irc     UnrealIRCd
8067/tcp  open  irc     UnrealIRCd
65534/tcp open  irc     UnrealIRCd
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (95%), Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.13 or 4.2 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.2 (95%), Linux 4.4 (95%), Linux 4.8 (95%), Linux 3.16 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: irked.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   50.85 ms 10.10.14.1
2   50.99 ms 10.129.34.15

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 27 08:40:43 2023 -- 1 IP address (1 host up) scanned in 12.90 seconds
```
```bash
# Nmap 7.94SVN scan initiated Wed Dec 27 08:45:43 2023 as: nmap -p 6697,8067,65534 -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -oN nmap/irc-scan 10.129.34.15
Nmap scan report for irked.htb (10.129.34.15)
Host is up (0.052s latency).

PORT      STATE SERVICE VERSION
6697/tcp  open  irc     UnrealIRCd
| irc-botnet-channels: 
|_  ERROR: Closing Link: [10.10.14.48] (Too many unknown connections from your IP)
8067/tcp  open  irc     UnrealIRCd
| irc-botnet-channels: 
|_  ERROR: Closing Link: [10.10.14.48] (Too many unknown connections from your IP)
65534/tcp open  irc     UnrealIRCd
| irc-botnet-channels: 
|_  ERROR: Closing Link: [10.10.14.48] (Too many unknown connections from your IP)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 27 08:45:43 2023 -- 1 IP address (1 host up) scanned in 0.68 seconds
```
```bash
# Nmap 7.94SVN scan initiated Wed Dec 27 08:50:08 2023 as: nmap -p 111 -sV --script nfs* -oN nmap/nfs-scan 10.129.34.15
Nmap scan report for irked.htb (10.129.34.15)
Host is up (0.054s latency).

PORT    STATE SERVICE VERSION
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          32828/tcp   status
|   100024  1          33381/udp6  status
|   100024  1          36515/tcp6  status
|_  100024  1          48607/udp   status

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 27 08:50:15 2023 -- 1 IP address (1 host up) scanned in 6.85 seconds
```
```bash
# Nmap 7.94SVN scan initiated Wed Dec 27 09:09:18 2023 as: nmap -p 111,5353,48607 -sU -sCV -oN nmap/udp-scan 10.129.34.15
Nmap scan report for irked.htb (10.129.34.15)
Host is up (0.051s latency).

PORT      STATE SERVICE VERSION
111/udp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          32828/tcp   status
|   100024  1          33381/udp6  status
|   100024  1          36515/tcp6  status
|_  100024  1          48607/udp   status
5353/udp  open  mdns    DNS-based service discovery
| dns-service-discovery: 
|   9/tcp workstation
|     Address=10.129.34.15 dead:beef::250:56ff:fe96:9dcd
|   80/tcp http
|_    Address=10.129.34.15 dead:beef::250:56ff:fe96:9dcd
48607/udp open  status  1 (RPC #100024)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 27 09:09:24 2023 -- 1 IP address (1 host up) scanned in 5.86 seconds
```