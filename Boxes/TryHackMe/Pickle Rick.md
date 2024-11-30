# Nmap

```bash
# Nmap 7.94SVN scan initiated Tue Nov 26 17:50:33 2024 as: /usr/lib/nmap/nmap -p- --min-rate=10000 --open -oG scans/quick-scan 10.10.213.243
Host: 10.10.213.243 () Status: Up
Host: 10.10.213.243 () Ports: 22/open/tcp//ssh///, 80/open/tcp//http/// Ignored State: closed (65533)
# Nmap done at Tue Nov 26 17:50:40 2024 -- 1 IP address (1 host up) scanned in 6.94 seconds
```

# Foothold
username in index page source code: R1ckRul3s

Fuzzing:
[http://10.10.203.64/robots.txt](http://10.10.203.64/robots.txt) - password Wubbalubbadubdub
[http://10.10.203.64/login.php](http://10.10.203.64/login.php) - we got valid credentials R1ckRul3s:Wubbalubbadubdub

We can get a shell with python3 revshell, then with `sudo -l` we see that we can run `sudo su` and become root