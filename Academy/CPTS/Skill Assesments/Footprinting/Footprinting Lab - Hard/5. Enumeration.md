## Nmap

### TCP Ports
```bash
# Nmap 7.94 scan initiated Tue Jul  4 11:38:29 2023 as: nmap -p 22,110,143,993,995 -sVC -A -oA /home/kali/Documents/Academy/Footprinting/Labs/Hard/nmap/service-scan 10.129.231.154
Nmap scan report for 10.129.231.154
Host is up (0.045s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: RESP-CODES TOP UIDL STLS USER AUTH-RESP-CODE SASL(PLAIN) CAPA PIPELINING
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_ssl-date: TLS randomness does not represent time
143/tcp open  imap     Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: post-login ID LOGIN-REFERRALS have AUTH=PLAINA0001 IMAP4rev1 IDLE Pre-login ENABLE STARTTLS listed capabilities SASL-IR LITERAL+ OK more
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
|_imap-capabilities: post-login AUTH=PLAINA0001 LOGIN-REFERRALS have ENABLE IDLE IMAP4rev1 Pre-login ID listed capabilities SASL-IR LITERAL+ OK more
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_ssl-date: TLS randomness does not represent time
995/tcp open  ssl/pop3 Dovecot pop3d
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_pop3-capabilities: CAPA RESP-CODES TOP USER AUTH-RESP-CODE SASL(PLAIN) UIDL PIPELINING
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul  4 11:38:46 2023 -- 1 IP address (1 host up) scanned in 17.51 seconds
```

### UDP Ports
```bash
# Nmap 7.94 scan initiated Tue Jul  4 11:39:18 2023 as: nmap -sU -p 161 -sVC -A -oA nmap/service-udp-scan 10.129.231.154
Nmap scan report for 10.129.231.154
Host is up (0.048s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    net-snmp; net-snmp SNMPv3 server
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 5b99e75a10288b6100000000
|   snmpEngineBoots: 10
|_  snmpEngineTime: 8m23s
Too many fingerprints match this host to give specific OS details
Network Distance: 2 hops

TRACEROUTE (using port 161/udp)
HOP RTT      ADDRESS
1   47.83 ms 10.10.14.1
2   ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul  4 11:39:39 2023 -- 1 IP address (1 host up) scanned in 21.79 seconds
```