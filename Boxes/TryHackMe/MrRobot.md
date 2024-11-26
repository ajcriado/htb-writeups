# Nmap
```bash
# Nmap 7.94SVN scan initiated Tue Nov 26 11:47:37 2024 as: /usr/lib/nmap/nmap --privileged -p- --open -oG scans/all-scan -v 10.10.249.72
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.249.72 ()	Status: Up
Host: 10.10.249.72 ()	Ports: 80/open/tcp//http///, 443/open/tcp//https///
# Nmap done at Tue Nov 26 11:49:32 2024 -- 1 IP address (1 host up) scanned in 114.87 seconds
```

# Foothold
Wpscan: `wpscan --url [http://10.10.249.72/](http://10.10.249.72/) --api-token XXX`
- WordPress 4.3.1 ([http://10.10.249.72/ac4ff5e.html](http://10.10.249.72/ac4ff5e.html) - source code says WordPress 4.3.1)

Wordlist: [http://10.10.249.72/fsocity.dic](http://10.10.249.72/fsocity.dic) - The list has a lot of duplicate values, remove them
- Fuzzing with this list we found:
    - [http://10.10.249.72/license](http://10.10.249.72/license) (just a message: what you do just pull code from Rapid9 or some s@#% since when did you become a script kitty?)
    - [http://10.10.249.72/readme](http://10.10.249.72/readme) (just a message: I like where you head is at. However I'm not going to help you.)
- Fuzzing wp-login.php page we found user `elliot` and password `ER28-0652`
    - First we brute force the user parameter and filter the request for “Invalid username” text, then we brute force passwords and filter the request for “is incorrect” text
- With valid credentials access as elliot, modify theme introducing php code and execute it to get a reverse shell as daemon.

# Lateral movement
In robot home folder we find the password hash, introducing it in [https://crackstation.net/](https://crackstation.net/) we get password `abcdefghijklmnopqrstuvwxyz`

# Privilege escalation
With linpeas we found that nmap has SUID bit set:
	`-rwsr-xr-x 1 root root 493K Nov 13 2015 /usr/local/bin/nmap`

In [https://gtfobins.github.io/gtfobins/nmap/#sudo](https://gtfobins.github.io/gtfobins/nmap/#sudo) we find that we can spawn a shell with nmap:
	`nmap --interactive`
	`!whoami`
	`!sh`