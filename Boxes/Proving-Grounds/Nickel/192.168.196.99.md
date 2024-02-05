### ++ Approach ++
#### Credentials
	* ariah:NowiseSloopTheory139 (SSH)
	* FTP pdf: ariah4168

#### Services
	##### 21 FTP
		- No anonymous login
		- With ariag credentials we can download the file Infraestructure.pdf which we have to crack with pdf2john (pass: ariah4168)

	##### 22 SSH
		- Access with ariah credentials (Found in Vuln 1)

	##### 80 Http
		- Server not working
		- Running in the machine in localhost, with port forwarding we can access and is a cmd as nt authority\system

	##### 135,49664-69 RCP
		- No null session

	##### 139,445 SMB
		- No null session

	##### 3389 RDP
		-

	##### 5040 ?
		-

	##### 8089 Http
		-

	##### 33333 Http
		- Verb tampering in /list-running-procs

### ++ Vulnerabilities ++

#### Vuln 1: Http verb tampering (list-running-procs API)
	* Changing GET to POST retrieve sensitive information (http://192.168.196.99:33333/list-running-procs)

#### Vuln 2: System shell publish in localhost server
	* With port forwarding we can expose the server running locally on port 80, which has a nt authority shell

### ++ System Interaction ++
#### Foothold  
	* In Vuln 1 we found user ariah and b64 password, we can SSH

#### Privilege Escalation 
	* In FTP we found a PDF which we crack and found "Temporary Command endpoint: http://nickel/?"
	* With `netstat -an` we found a http server running in localhost, which we reach by using port forwarding. Once we reach the server we discover that is a cmd and we can launch commands like http://localhost/?whoami

#### Attack chain
	* With verb tampering in http://192.168.196.99:33333/list-running-procs we get credentials (b64 encoded password)
	* Found PDF in FTP told us about a web server
	* Expose this web server with port-forwarding and get a shell as nt authority
	
#### Post-exploitation 
	-
	
### ++ Scripts and Images ++
#### Nmap
```bash
# Nmap 7.94SVN scan initiated Mon Feb  5 19:02:39 2024 as: /usr/bin/nmap -Pn -sCV -p21,22,80,135,139,445,3389,5040,8089,33333,49664,49665,49666,49667,49668,49669 --open -oN nmap/Script_TCP_192.168.196.99.nmap --system-dns --stats-every 2s 192.168.196.99
Nmap scan report for 192.168.196.99
Host is up (0.030s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 86:84:fd:d5:43:27:05:cf:a7:f2:e9:e2:75:70:d5:f3 (RSA)
|   256 9c:93:cf:48:a9:4e:70:f4:60:de:e1:a9:c2:c0:b6:ff (ECDSA)
|_  256 00:4e:d7:3b:0f:9f:e3:74:4d:04:99:0b:b1:8b:de:a5 (ED25519)
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: NICKEL
|   NetBIOS_Domain_Name: NICKEL
|   NetBIOS_Computer_Name: NICKEL
|   DNS_Domain_Name: nickel
|   DNS_Computer_Name: nickel
|   Product_Version: 10.0.18362
|_  System_Time: 2024-02-05T18:05:27+00:00
|_ssl-date: 2024-02-05T18:06:34+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=nickel
| Not valid before: 2024-01-29T02:08:16
|_Not valid after:  2024-07-30T02:08:16
5040/tcp  open  unknown
8089/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
|_http-server-header: Microsoft-HTTPAPI/2.0
33333/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-02-05T18:05:27
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Feb  5 19:06:35 2024 -- 1 IP address (1 host up) scanned in 236.15 seconds
```

#### Images