#### Nmap

```bash
# Nmap 7.94SVN scan initiated Tue Jan  2 17:41:17 2024 as: nmap -p 22,80 -sCV -A -T4 -O -oN nmap/port-scan 10.129.28.138
Nmap scan report for 10.129.28.138
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
|_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Site doesnt have a title (text/html; charset=UTF-8).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|storage-misc
Running (JUST GUESSING): Linux 5.X|3.X|4.X (91%), Crestron 2-Series (86%), HP embedded (85%), Oracle VM Server 3.X (85%)
OS CPE: cpe:/o:linux:linux_kernel:5.0 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3 cpe:/o:oracle:vm_server:3.4.2 cpe:/o:linux:linux_kernel:4.1
Aggressive OS guesses: Linux 5.0 (91%), Linux 3.10 - 4.11 (90%), Linux 3.2 - 4.9 (90%), Linux 5.1 (90%), Linux 3.18 (88%), Crestron XPanel control system (86%), Linux 3.16 (86%), HP P2000 G3 NAS device (85%), Oracle VM Server 3.4.2 (Linux 4.1) (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   114.73 ms 10.10.14.1
2   116.19 ms 10.129.28.138

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan  2 17:41:39 2024 -- 1 IP address (1 host up) scanned in 21.34 seconds
```

#### Dirsearch

```bash
# dirsearch -u http://10.129.28.138:80/
[17:48:10] 301 -  236B  - /backup  ->  http://10.129.28.138/backup/         
[17:48:10] 200 -  885B  - /backup/                                 
```

#### Found script 1

```bash
check_attack.php

<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";
  
$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
$msg='';
if ($value == 'index.html') {
continue;
}

#echo "-------------\n";
  
#print "check: $value\n";
list ($name,$ext) = getnameCheck($value);
$check = check_ip($name,$value);
  
if (!($check[0])) {
echo "attack!\n";
# todo: attach file
file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

exec("rm -f $logpath");
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
echo "rm -f $path$value\n";
mail($to, $msg, $msg, $headers, "-F$value");
}
}

?>
```

#### Found script 2

```bash
changename.sh

#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```