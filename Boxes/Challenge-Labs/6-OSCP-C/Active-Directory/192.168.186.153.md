### ++ Approach 192.168.186.153 ++
#### Credentials
	* support:Freedom1 (WinRM, SSH)
    * administrator:December31 (WinRM, SSH)
    * web_svc:Diamond1

#### Services
	##### 22 SSH
		- 

	##### 135 RPC
		-

	##### 139,445 SMB
		-

	##### 5985,47001 WinRM
		-

	##### 8000 Http
		/partner/db here we find a sqlite database with credentials support:Freedom1

### ++ Vulnerabilities ++

#### Vuln 1: Sensitive information exposed in 8000/partner/db ++
	* Here we can find a sqlite database with crackable user hashes

### ++ System Interaction ++
#### Foothold
	* Abusing vuln 1 we can get a shell through SSH/WinRM as support user

#### Privilege Escalation 
	* In C:\Users\support we find a binary called admintool.exe which gives us the admin hash if we execute it entering a wrong password
    * Output:
        support@MS01 C:\Users\support>.\admintool.exe whoami
        Enter administrator password:

        thread 'main' panicked at 'assertion failed: `(left == right)`
        left: `"d41d8cd98f00b204e9800998ecf8427e"`,
        right: `"05f8ba9f047f799adbea95a16de2ef5d"`: Wrong administrator password!', src/main.rs:78:5
        note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
    * Creds: administrator:December31

#### Attack chain
	* -
	
#### Post-exploitation 
	* Kerberoasting:
        web_svc:Diamond1
        sql_svc (No cracked)