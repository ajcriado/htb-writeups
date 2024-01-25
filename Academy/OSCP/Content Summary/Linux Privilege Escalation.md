**[Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)**

There are several key pieces of information we should always obtain:
```text
- User context
	# id
	# cat /etc/passwd (check write permissions)
	# hostname
	# sudo -l
- Abuse Setuid Binaries and Capabilities
	# /usr/sbin/getcap -r / 2>/dev/null (Find cap_setuid+ep, even grep by cap_setuid)
- Directories writable by the current user
	# find / -writable -type d 2>/dev/null
- Scheduled tasks
	# ls -lah /etc/cron*
	# sudo crontab -l
	# grep "CRON" /var/log/syslog
- Information about the operating system release and version
	# cat /etc/issue
	# cat /etc/os-release
	# uname -a
- Processes (Also execute PSPY binary)
	# ps aux
- Check for multiple networks to pivot
	# ip a
	# route
- Connections
	# ss -tulpn
- Applications
	# dpkg -l
- Mounted filesystems
	# cat /etc/fstab
	# mount
- Available disks
	# lsblk
- Kernel loaded modules
	# lsmod
	# /sbin/modinfo <loaded module> (find out more about the specific module)
- SUID-marked binaries
	# find / -perm -u=s -type f 2>/dev/null
- Environment variables
	# env
- Bash configuration and history
	# cat .bashrc
	# cat .bash_history
```

After this enumeration, execute **[my script](https://github.com/ajcriado/burbles-by-peluqqi)** and then launch **unix-privesc-check** and **linpeas.sh**. If nothing found, check **pspy** and inspect the processes

Let's try to capture traffic in and out of the loopback interface, then dump its content in ASCII using the **-A** parameter. Ultimately, we want to filter any traffic containing the "pass" keyword.

```text
joe@debian-privesc:~$ sudo tcpdump -i lo -A | grep "pass"
[sudo] password for joe:
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
...{...zuser:root,pass:lab -
...5...5user:root,pass:lab -
```