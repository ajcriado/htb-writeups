172.16.5.225
Linux

```bash
Nmap scan report for 172.16.5.225
Host is up (0.068s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 97:cc:9f:d0:a3:84:da:d1:a2:01:58:a1:f2:71:37:e5 (RSA)
|   256 03:15:a9:1c:84:26:87:b7:5f:8d:72:73:9f:96:e0:f2 (ECDSA)
|_  256 55:c9:4a:d2:63:8b:5f:f2:ed:7b:4e:38:e1:c9:f5:71 (ED25519)
80/tcp   open  http          nginx 1.21.6
|_http-title: Did not follow redirect to https://172.16.5.225/
|_http-server-header: nginx/1.21.6
443/tcp  open  ssl/http      nginx 1.21.6
|_http-server-header: nginx/1.21.6
| ssl-cert: Subject: commonName=writehat.corp.local/organizationName=Black Lantern Security/stateOrProvinceName=SC/countryName=US
| Not valid before: 2020-11-20T14:26:49
|_Not valid after:  2048-04-06T14:26:49
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_ssl-date: TLS randomness does not represent time
| http-title: WH - WriteHat - Log In
|_Requested resource was /login?next=/
1234/tcp open  http          SimpleHTTPServer 0.6 (Python 3.9.2)
3389/tcp open  ms-wbt-server xrdp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (5 hosts up) scanned in 334.17 seconds
```