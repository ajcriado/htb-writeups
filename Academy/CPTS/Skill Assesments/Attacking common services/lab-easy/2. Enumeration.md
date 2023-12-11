### Nmap

```bash
┌──(kali㉿kali)-[~/Documents/Academy/Attacking-common-services/lab-easy]
└─$ nmap -p21,25,80,443,587,3306,3389 10.129.203.7 -sC -sV -A -T4 10.129.203.7 -oA nmap/services
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-16 11:56 CEST
Nmap scan report for 10.129.203.7
Host is up (0.25s latency).                                                 
                                                                            
PORT     STATE SERVICE       VERSION                                        
21/tcp   open  ftp                                                          
|_ssl-date: 2023-08-16T09:59:06+00:00; +1s from scanner time.               
| fingerprint-strings:                                                      
|   GenericLines:                                                           
|     220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered       
|     Command unknown, not supported or not allowed...                      
|     Command unknown, not supported or not allowed...                      
|   NULL:                                                                   
|_    220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered       
25/tcp   open  smtp          hMailServer smtpd                              
| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP            
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY               
80/tcp   open  http          Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
|_http-server-header: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/7.4.29
| http-title: Welcome to XAMPP
|_Requested resource was http://10.129.203.7/dashboard/
443/tcp  open  https?
| ssl-cert: Subject: commonName=Test/organizationName=Testing/stateOrProvinceName=FL/countryName=US
| Not valid before: 2022-04-21T19:27:17
|_Not valid after:  2032-04-18T19:27:17
|_ssl-date: 2023-08-16T09:59:06+00:00; +1s from scanner time.
587/tcp  open  smtp          hMailServer smtpd
| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
3306/tcp open  mysql         MySQL 5.5.5-10.4.24-MariaDB
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.4.24-MariaDB
|   Thread ID: 15
|   Capabilities flags: 63486
|   Some Capabilities: FoundRows, LongColumnFlag, Speaks41ProtocolOld, ConnectWithDatabase, SupportsTransactions, DontAllowDatabaseTableColumn, SupportsCompression, InteractiveClient, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, ODBCClient, SupportsLoadDataLocal, IgnoreSigpipes, Support41Auth, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: vg!ju0,,9uf~hkb,R7[G
|_  Auth Plugin Name: mysql_native_password
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WIN-EASY
| Not valid before: 2023-08-15T09:50:52
|_Not valid after:  2024-02-14T09:50:52
| rdp-ntlm-info: 
|   Target_Name: WIN-EASY
|   NetBIOS_Domain_Name: WIN-EASY
|   NetBIOS_Computer_Name: WIN-EASY
|   DNS_Domain_Name: WIN-EASY
|   DNS_Computer_Name: WIN-EASY
|   Product_Version: 10.0.17763
|_  System_Time: 2023-08-16T09:58:07+00:00
|_ssl-date: 2023-08-16T09:59:05+00:00; 0s from scanner time.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94%I=7%D=8/16%Time=64DC9D72%P=x86_64-pc-linux-gnu%r(NULL
SF:,41,"220\x20Core\x20FTP\x20Server\x20Version\x202\.0,\x20build\x20725,\
SF:x2064-bit\x20Unregistered\r\n")%r(GenericLines,AD,"220\x20Core\x20FTP\x
SF:20Server\x20Version\x202\.0,\x20build\x20725,\x2064-bit\x20Unregistered
SF:\r\n502\x20Command\x20unknown,\x20not\x20supported\x20or\x20not\x20allo
SF:wed\.\.\.\r\n502\x20Command\x20unknown,\x20not\x20supported\x20or\x20no
SF:t\x20allowed\.\.\.\r\n");
Service Info: Host: WIN-EASY; OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap scan report for 10.129.203.7
Host is up (0.25s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered
|     Command unknown, not supported or not allowed...
|     Command unknown, not supported or not allowed...
|   NULL: 
|_    220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered
| ssl-cert: Subject: commonName=Test/organizationName=Testing/stateOrProvinceName=FL/countryName=US
| Not valid before: 2022-04-21T19:27:17
|_Not valid after:  2032-04-18T19:27:17
25/tcp   open  smtp          hMailServer smtpd
| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp   open  http          Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
|_http-server-header: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/7.4.29
| http-title: Welcome to XAMPP
|_Requested resource was http://10.129.203.7/dashboard/
443/tcp  open  https?
|_ssl-date: 2023-08-16T09:59:05+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=Test/organizationName=Testing/stateOrProvinceName=FL/countryName=US
| Not valid before: 2022-04-21T19:27:17
|_Not valid after:  2032-04-18T19:27:17
587/tcp  open  smtp          hMailServer smtpd
| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
3306/tcp open  mysql         MySQL 5.5.5-10.4.24-MariaDB
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.4.24-MariaDB
|   Thread ID: 16
|   Capabilities flags: 63486
|   Some Capabilities: FoundRows, LongColumnFlag, Speaks41ProtocolOld, ConnectWithDatabase, SupportsTransactions, DontAllowDatabaseTableColumn, SupportsCompression, InteractiveClient, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, ODBCClient, SupportsLoadDataLocal, IgnoreSigpipes, Support41Auth, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: AZ#:=bXnDH{Vx{~*P8et
|_  Auth Plugin Name: mysql_native_password
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: WIN-EASY
|   NetBIOS_Domain_Name: WIN-EASY
|   NetBIOS_Computer_Name: WIN-EASY
|   DNS_Domain_Name: WIN-EASY
|   DNS_Computer_Name: WIN-EASY
|   Product_Version: 10.0.17763
|_  System_Time: 2023-08-16T09:58:05+00:00
|_ssl-date: 2023-08-16T09:59:05+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=WIN-EASY
| Not valid before: 2023-08-15T09:50:52
|_Not valid after:  2024-02-14T09:50:52
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94%I=7%D=8/16%Time=64DC9D72%P=x86_64-pc-linux-gnu%r(NULL
SF:,41,"220\x20Core\x20FTP\x20Server\x20Version\x202\.0,\x20build\x20725,\
SF:x2064-bit\x20Unregistered\r\n")%r(GenericLines,AD,"220\x20Core\x20FTP\x
SF:20Server\x20Version\x202\.0,\x20build\x20725,\x2064-bit\x20Unregistered
SF:\r\n502\x20Command\x20unknown,\x20not\x20supported\x20or\x20not\x20allo
SF:wed\.\.\.\r\n502\x20Command\x20unknown,\x20not\x20supported\x20or\x20no
SF:t\x20allowed\.\.\.\r\n");
Service Info: Host: WIN-EASY; OS: Windows; CPE: cpe:/o:microsoft:windows

Post-scan script results:
| clock-skew: 
|   0s: 
|     10.129.203.7
|_    10.129.203.7
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 2 IP addresses (2 hosts up) scanned in 139.87 seconds
```