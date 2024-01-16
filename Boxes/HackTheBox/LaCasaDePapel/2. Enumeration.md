
### Nmap

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p21,22,80,443 -sCV -A -T4 -O 10.10.10.131 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-26 12:20 CEST
Nmap scan report for 10.10.10.131
Host is up (0.044s latency).

PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 2.3.4
22/tcp  open  ssh      OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:e1:c2:c9:79:1c:a6:6b:51:34:8d:7a:c3:c7:c8:50 (RSA)
|   256 41:e4:95:a3:39:0b:25:f9:da:de:be:6a:dc:59:48:6d (ECDSA)
|_  256 30:0b:c6:66:2b:8f:5e:4f:26:28:75:0e:f5:b1:71:e4 (ED25519)
80/tcp  open  http     Node.js (Express middleware)
|_http-title: La Casa De Papel
443/tcp open  ssl/http Node.js Express framework
|_http-title: La Casa De Papel
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Not valid before: 2019-01-27T08:35:30
|_Not valid after:  2029-01-24T08:35:30
| tls-nextprotoneg: 
|   http/1.1
|_  http/1.0
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (96%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), Linux 3.16 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 5.1 (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%), Android 4.1.1 (93%), Linux 3.18 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Unix

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   32.35 ms 10.10.14.1
2   32.73 ms 10.10.10.131

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.71 seconds
```


### Whatweb / Curl

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/LaCasaDePapel-10.10.10.131]
└─$ whatweb http://10.10.10.131:80/  
http://10.10.10.131:80/ [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.10.10.131], Title[La Casa De Papel], X-Powered-By[Express]   

┌──(kali㉿kali)-[~/Documents/Boxes/LaCasaDePapel-10.10.10.131]
└─$ curl http://10.10.10.131:80/
<!DOCTYPE html><html lang="en"><head><title>La Casa De Papel</title><style type="text/css">body {
    text-align:center;
    width:100%;
    margin:0 auto;
    padding:0px;
    font-family:Courier;
    background-color:#000;

    background: url(casa.jpg) no-repeat center center fixed; 
    -webkit-background-size: cover;
    -moz-background-size: cover;
    -o-background-size: cover;
    background-size: cover;
}
div {
    position: absolute;
    top: 50%;
    left: 50%;
    margin-left:-100px;
    margin-top:-50px;
}
a {
  color: #aaa;
  font-size: 10px;
  font-weight: bold;
  text-decoration:none;
  background:black;
  padding:2px 4px;
}
a:hover {
  color: #fff;
}
input[type="image"] {
  display: block; 
  width: 200px;
}
input[type="email"],input[type="text"] {
  background: white;
  color: black;
  padding: 8px 0;
  font-size: 10px;
  font-weight: bold;
  display: block;
  width: 200px;
  margin: 5px 0;
  text-align: center;
  border: 0;
}
button {
  background: #e50914;
  color: #fff;
  width: 200px;
  padding: 10px 0;
  margin: 5px 0;
  border: 0;
  cursor: pointer;
}</style></head><body><div><form method="POST"><input type="image" src="/qrcode?qrurl=otpauth%3A%2F%2Fhotp%2FToken%3Fsecret%3DGFBWIVJ2IEYCGN2YGUUC64TSGY3VOLCU%26algorithm%3DSHA1" readonly="readonly" onclick="return false"><input name="secret" type="hidden" value="GFBWIVJ2IEYCGN2YGUUC64TSGY3VOLCU"><input name="token" type="text" placeholder="ONE PASSWORD" autocomplete="off"><a target="_blank" href="https://support.google.com/accounts/answer/1066447?co=GENIE.Platform%3DAndroid&amp;hl=en&amp;oco=0">Install Google Authenticator</a><input name="email" type="email" placeholder="E-MAIL" autocomplete="off"><button>GET FREE TRIAL</button></form></div></body></html>
```

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/LaCasaDePapel-10.10.10.131]
└─$ whatweb https://10.10.10.131:443/
https://10.10.10.131:443/ [401 Unauthorized] Country[RESERVED][ZZ], HTML5, IP[10.10.10.131], Title[La Casa De Papel], X-Powered-By[Express]

┌──(kali㉿kali)-[~/Documents/Boxes/LaCasaDePapel-10.10.10.131]
└─$ curl https://10.10.10.131:443/ --insecure
<!DOCTYPE html><html lang="en"><head><title>La Casa De Papel</title><style type="text/css">body {
    text-align:center;
    width:100%;
    margin:0 auto;
    padding:0px;
    font-family:Courier;
    background-color:#000;

    background: url(casa.jpg) no-repeat center center fixed; 
    -webkit-background-size: cover;
    -moz-background-size: cover;
    -o-background-size: cover;
    background-size: cover;
}
div {
    position: absolute;
    top: 50%;
    left: 50%;
    margin-left:-120px;
    margin-top:-50px;
    background: black;
}
h1 {
  color: red;
  font-size: 16px;
  font-weight: bold;
}
p {
  color: white;
  padding:0px 20px;
  font-size: 12px;
  font-weight: bold;
  width:150px;
}
img {
  display: block; 
  width: 150px;
  margin-left:25px;
}</style></head><body><div><h1>CERTIFICATE ERROR</h1><img src="dali.jpg"><p>Sorry, but you need to provide a client certificate to continue.</p></div></body></html>
```

