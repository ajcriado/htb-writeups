
| **Directory enumeration**                                                 | **Description**                              |
| ------------------------------------------------------------------------- | -------------------------------------------- |
| `/usr/share/wordlists/dirb/common.txt`                                    | Common resources                             |
| `/usr/share/wordlists/dirb/big.txt`                                       | Big resources file                           |
| `/usr/share/wordlists/dirb/small.txt`                                     | Small resources file                         |
| `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt`  | CPTS main wordlist for directory discovering |
| `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` |                                              |
| `/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt`         | Fuzzing for API                              |
| `/usr/share/secLists/Discovery/Web-Content/web-extensions.txt`            | Fuzzing for web extensions                   |
| `/usr/share/seclists/Discovery/Web-Content/common.txt`                    | Common values from seclists                  |
| `/usr/share/wordlists/dirb/common.txt`                                    | Common values from dirb                      |

| **Passwords** | **Description** |
| ---- | ---- |
| `/usr/share/wordlists/rockyou.txt` | Rockyou |
| `ls -la /usr/share/hashcat/rules/` | List of rules for hash cracking |
| `/usr/share/hashcat/rules/best64` | best64 rule |

| **Usernames**                                   | **Description**                                               |
| ----------------------------------------------- | ------------------------------------------------------------- |
| `/usr/share/wordlists/dirb/others/names.txt`    | Dirb usernames                                                |
| `/usr/share/seclists/Usernames/Names/names.txt` | List used to enumerate users in SMTP / Also for CPTS usenames |

Custom wordlists:
* **[Cewl:](https://github.com/digininja/CeWL)** create custom wordlists by webpage url
* **[Cupp:](https://github.com/Mebus/cupp)** create custom wordlist by user info (parents, birthdate, etc.)
* **[Username-anarchy:](https://github.com/urbanadventurer/username-anarchy.git)** create custom wordlist by user name