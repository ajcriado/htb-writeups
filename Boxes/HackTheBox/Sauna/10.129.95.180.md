### ++ Approach 10.129.95.180 ++
#### Credentials
	* fsmith:Thestrokes23 (egotistical-bank.local)
    * svc_loanmgr:Moneymakestheworldgoround! (egotistical-bank.local)

#### Services
	##### 53 DNS
		Domain: egotistical-bank.local

	##### 80 Http
		In /about.html we find users and we create a wordlist with **[username-wordlist-generator](https://github.com/captain-noob/username-wordlist-generator)**

	##### 389,3268 Ldap
		-

	##### 135 RPC
		-

	##### 139,445 SMB
		-

	##### 5985 WinRM
		-

### ++ Vulnerabilities ++

#### Vuln 1: With ASPREPRoast we can get fsmith password ++
	* Command: impacket-GetNPUsers egotistical-bank.local/ -usersfile users-list.txt -format hashcat -outputfile hashes.asreproast
    * After crack it: fsmith:Thestrokes23

### ++ System Interaction ++
#### Foothold  
	* Abuse vuln 1 and get fsmith credentials with ASREPRoasting

#### Lateral Movement as svc_loanmgr
	* With winpeas we found autologon credentials for svc_loanmgr:Moneymakestheworldgoround! and we can use WinRM

#### Privilege Escalation 
	* svc_loanmgr has DCSync privilege, so we can abuse it with mimikatz or impacket-secretsdump:
        impacket-secretsdump -just-dc-user administrator egotistical-bank.local/svc_loanmgr:"Moneymakestheworldgoround\!"@10.129.36.63
    * We get administrator hash so we can use pass-the-hash with evil-winrm

#### Attack chain
	* Create a user list from webapp in port 80 and perform ASPREPRoast from linux to get a foothold as fsmith
    * Find autologon credentials with winpeas for svc_loanmgr
    * Perform DCSync attack to get administrator hash