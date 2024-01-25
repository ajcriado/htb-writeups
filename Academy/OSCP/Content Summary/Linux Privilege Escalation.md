**[Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)**

There are several key pieces of information we should always obtain:
```text
- User context
	# id
	# cat /etc/passwd
	# hostname
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
- Scheduled tasks
	# ls -lah /etc/cron*
	# sudo crontab -l
- Applications
	# dpkg -l
- Directories writable by the current user
	# find / -writable -type d 2>/dev/null
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
```