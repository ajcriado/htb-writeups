#### Brute Forcing

> [!info]  Always try default passwords, and username as password if we have some users

**First of all, brute force with basic usernames and passwords:**
* **Basic usernames:** `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`
* **Basic passwords:** `/usr/share/seclists/Passwords/Leaked-Databases/rockyou-10.txt`

| **Brute force**                                                                                                                                           | **Description**                              |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| `hydra -l george -P /usr/share/wordlists/rockyou.txt -e nsr -s 2222 ssh://192.168.50.201 -vV`                                                             | SSH                                          |
| `hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" -e nsr rdp://192.168.50.202 -vV`                                               | RDP - Password spraying                      |
| `hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 -e nsr http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid" -vV` | HTTP Form                                    |
| `hydra -l admin -P /usr/share/wordlists/rockyou.txt -e nsr -f ftp://192.168.213.61 -vV`                                                                   | FTP                                          |
| `hydra -L users.txt -P cewl-list.txt -e nsr -f 192.168.235.137 imap -u -f -vV`                                                                            | IMAP                                         |
| `hydra -L wordlist.txt -P wordlist.txt -e nsr -u -f SERVER_IP -s PORT http-get / -vV`                                                                     | Basic Auth Brute Force - User/Pass Wordlists |

#### Hash cracking

> [!info] We can use Hash-identifier in kali linux to find the hash type

Find Hashcat modes for specific hash type:
```bash
hashcat --help | grep -i "ntlm"
```

| **Hash cracking** | **Description** |
| ---- | ---- |
| `hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force` | Hashcat NTLM hash with rule (we can skip the rule) |
| `john --wordlist=/usr/share/wordlists/rockyou.txt --rules=/usr/share/hashcat/rules/best64.rule ssh.hash` | John the Ripper with rule (we can skip the rule) |
