#### Users

* wario:Mushroom! (WinRm)
* leon:rabbit:)
* Administrator:e8deb837a4d5457650813446f38c0e77 (WinRm)

#### Foothold

* Wario can WinRM here as user

#### Privilege Escalation

* We abuse the file located in C:\ŦEMP\backup.exe using a reverse shell and we got nt authority\system

#### Post-exploitation

* Dump credentials and found leon hash, who is DC admin

#### Nmap

```bash
# Nmap 7.94SVN scan initiated Wed Jan 31 22:46:39 2024 as: nmap -p 135,139,445,49665,49668,49669 -sCV -A -T4 -O -oN 172.16.216.83/nmap/port-scan.nmap 172.16.216.83
Nmap scan report for 172.16.216.83
Host is up (0.045s latency).
Not shown: 65522 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc?
139/tcp   open  netbios-ssn?
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  winrm?
| fingerprint-strings: 
|   JavaRMI: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html; charset=us-ascii
|     Server: Microsoft-HTTPAPI/2.0
|     Date: Fri, 02 Feb 2024 11:20:03 GMT
|     Connection: close
|     Content-Length: 326
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
|     <HTML><HEAD><TITLE>Bad Request</TITLE>
|     <META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
|     <BODY><h2>Bad Request - Invalid Verb</h2>
|     <hr><p>HTTP Error 400. The request verb is invalid.</p>
|_    </BODY></HTML>
49664/tcp open  unknown
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: CLIENT02, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:9e:97:65 (VMware)
| smb2-time: 
|   date: 2024-02-01T13:32:22
|_  start_date: N/A
|_clock-skew: -1s
```