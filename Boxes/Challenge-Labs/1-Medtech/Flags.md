172.16.216.10 Proof
172.16.216.11 Local and Proof
172.16.216.12 Local and Proof
172.16.216.13 Proof
172.16.216.82 Proof
172.16.216.83 Local and Proof
192.168.216.121 Proof
192.168.216.120 Proof
192.168.216.122 Local and Proof 
172.16.216.14 Local


Get-ADComputer -Filter * | Select-Object DNSHostName, @{name="Ip";Expression={(Test-Connection $_.DNSHostname -Count 1).IPV4Address.IPAddressToString}}
PS C:\> Get-ADComputer -Filter * | Select-Object DNSHostName, @{name="Ip";Expression={(Test-Connection $_.DNSHostname -Count 1).IPV4Address.IPAddressToString}}

DNSHostName           Ip            
-----------           --            
DC01.medtech.com      172.16.216.10 
FILES02.medtech.com   172.16.216.11 
DEV04.medtech.com     172.16.216.12 
CLIENT01.medtech.com  172.16.216.82 
PROD01.medtech.com    172.16.216.13 
CLIENT02.medtech.com  172.16.216.83 
WEB02.dmz.medtech.com 172.16.216.254



SKYLARK (For future use)

.223 - local + proof
.225 - local + proof
.221 - local + proof
.11 - proof
.13 - proof
.220  - local + proof
.250  - local + proof
.226 - local + proof
.222 - local
.227 - proof
.15 - local + proof
.110 - local + proof 
.111 - local + proof 
.10 - local  + proof
.14 - local  + proof
.12 - local + proof
.31 - local + proof
.32 - proof
.30 - local + proof
.224 - local +  proof