### Nmap

```bash
# Nmap 7.94SVN scan initiated Tue Jan  9 17:45:18 2024 as: nmap -p 135,139,445,1433,47001,49664,49665,49666,49667,49668,49669,49671 -sCV -A -T4 -O -oN nmap/port-scan 10.129.47.41
Nmap scan report for 10.129.47.41
Host is up (0.033s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-01-09T16:42:01
|_Not valid after:  2054-01-09T16:42:01
| ms-sql-info: 
|   10.129.47.41:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.129.47.41:1433: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: QUERIER
|     DNS_Domain_Name: HTB.LOCAL
|     DNS_Computer_Name: QUERIER.HTB.LOCAL
|     DNS_Tree_Name: HTB.LOCAL
|_    Product_Version: 10.0.17763
|_ssl-date: 2024-01-09T16:46:30+00:00; +1s from scanner time.
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows 2019|2012|2022|10|2016|2008|7|Vista|Longhorn (95%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_vista::sp1:home_premium cpe:/o:microsoft:windows cpe:/o:microsoft:windows_10:1511
Aggressive OS guesses: Microsoft Windows Server 2019 (95%), Microsoft Windows Server 2012 R2 (92%), Microsoft Windows Server 2022 (92%), Microsoft Windows 10 1909 (92%), Microsoft Windows 10 1709 - 1909 (87%), Microsoft Windows Server 2012 (87%), Microsoft Windows Server 2012 or Server 2012 R2 (87%), Microsoft Windows Server 2016 (87%), Microsoft Windows Server 2008 R2 (86%), Microsoft Windows 7 SP1 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-09T16:46:26
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   29.57 ms 10.10.14.1
2   29.70 ms 10.129.47.41

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan  9 17:46:29 2024 -- 1 IP address (1 host up) scanned in 71.28 seconds
```
