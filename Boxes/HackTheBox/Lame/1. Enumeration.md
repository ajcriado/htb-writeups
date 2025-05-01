```bash
# Nmap 7.95 scan initiated Mon Apr 28 10:47:23 2025 as: /usr/lib/nmap/nmap -p- --min-rate=5000 --open -oN scans/all-ports -v 10.10.10.3
Nmap scan report for 10.10.10.3
Host is up (0.043s latency).
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3632/tcp open  distccd

Read data files from: /usr/share/nmap
# Nmap done at Mon Apr 28 10:47:50 2025 -- 1 IP address (1 host up) scanned in 26.56 seconds
```

# Enum4linux

```bash
┌──(kali㉿kali)-[/Shared/CTFs/Hackthebox/Lame]
└─$ enum4linux 10.10.10.3 -A
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Apr 28 10:58:07 2025

 =========================================( Target Information )=========================================
                                                                                                                            
Target ........... 10.10.10.3                                                                                               
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =============================( Enumerating Workgroup/Domain on 10.10.10.3 )=============================
                                                                                                                            
                                                                                                                            
[E] Can't find workgroup/domain                                                                                             
                                                                                                                            
                                                                                                                            

 =================================( Nbtstat Information for 10.10.10.3 )=================================
                                                                                                                            
Looking up status of 10.10.10.3                                                                                             
No reply from 10.10.10.3

 ====================================( Session Check on 10.10.10.3 )====================================
                                                                                                                            
                                                                                                                            
[+] Server 10.10.10.3 allows sessions using username '', password ''                                                        
                                                                                                                            
                                                                                                                            
 =================================( Getting domain SID for 10.10.10.3 )=================================
                                                                                                                            
Domain Name: WORKGROUP                                                                                                      
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup                                                        
                                                                                                                            
                                                                                                                            
 ====================================( OS information on 10.10.10.3 )====================================
                                                                                                                            
                                                                                                                            
[E] Can't get OS info with smbclient                                                                                        
                                                                                                                            
                                                                                                                            
[+] Got OS info for 10.10.10.3 from srvinfo:                                                                                
        LAME           Wk Sv PrQ Unx NT SNT lame server (Samba 3.0.20-Debian)                                               
        platform_id     :       500
        os version      :       4.9
        server type     :       0x9a03


 ========================================( Users on 10.10.10.3 )========================================
                                                                                                                            
index: 0x1 RID: 0x3f2 acb: 0x00000011 Account: games    Name: games     Desc: (null)                                        
index: 0x2 RID: 0x1f5 acb: 0x00000011 Account: nobody   Name: nobody    Desc: (null)
index: 0x3 RID: 0x4ba acb: 0x00000011 Account: bind     Name: (null)    Desc: (null)
index: 0x4 RID: 0x402 acb: 0x00000011 Account: proxy    Name: proxy     Desc: (null)
index: 0x5 RID: 0x4b4 acb: 0x00000011 Account: syslog   Name: (null)    Desc: (null)
index: 0x6 RID: 0xbba acb: 0x00000010 Account: user     Name: just a user,111,, Desc: (null)
index: 0x7 RID: 0x42a acb: 0x00000011 Account: www-data Name: www-data  Desc: (null)
index: 0x8 RID: 0x3e8 acb: 0x00000011 Account: root     Name: root      Desc: (null)
index: 0x9 RID: 0x3fa acb: 0x00000011 Account: news     Name: news      Desc: (null)
index: 0xa RID: 0x4c0 acb: 0x00000011 Account: postgres Name: PostgreSQL administrator,,,       Desc: (null)
index: 0xb RID: 0x3ec acb: 0x00000011 Account: bin      Name: bin       Desc: (null)
index: 0xc RID: 0x3f8 acb: 0x00000011 Account: mail     Name: mail      Desc: (null)
index: 0xd RID: 0x4c6 acb: 0x00000011 Account: distccd  Name: (null)    Desc: (null)
index: 0xe RID: 0x4ca acb: 0x00000011 Account: proftpd  Name: (null)    Desc: (null)
index: 0xf RID: 0x4b2 acb: 0x00000011 Account: dhcp     Name: (null)    Desc: (null)
index: 0x10 RID: 0x3ea acb: 0x00000011 Account: daemon  Name: daemon    Desc: (null)
index: 0x11 RID: 0x4b8 acb: 0x00000011 Account: sshd    Name: (null)    Desc: (null)
index: 0x12 RID: 0x3f4 acb: 0x00000011 Account: man     Name: man       Desc: (null)
index: 0x13 RID: 0x3f6 acb: 0x00000011 Account: lp      Name: lp        Desc: (null)
index: 0x14 RID: 0x4c2 acb: 0x00000011 Account: mysql   Name: MySQL Server,,,   Desc: (null)
index: 0x15 RID: 0x43a acb: 0x00000011 Account: gnats   Name: Gnats Bug-Reporting System (admin)        Desc: (null)
index: 0x16 RID: 0x4b0 acb: 0x00000011 Account: libuuid Name: (null)    Desc: (null)
index: 0x17 RID: 0x42c acb: 0x00000011 Account: backup  Name: backup    Desc: (null)
index: 0x18 RID: 0xbb8 acb: 0x00000010 Account: msfadmin        Name: msfadmin,,,       Desc: (null)
index: 0x19 RID: 0x4c8 acb: 0x00000011 Account: telnetd Name: (null)    Desc: (null)
index: 0x1a RID: 0x3ee acb: 0x00000011 Account: sys     Name: sys       Desc: (null)
index: 0x1b RID: 0x4b6 acb: 0x00000011 Account: klog    Name: (null)    Desc: (null)
index: 0x1c RID: 0x4bc acb: 0x00000011 Account: postfix Name: (null)    Desc: (null)
index: 0x1d RID: 0xbbc acb: 0x00000011 Account: service Name: ,,,       Desc: (null)
index: 0x1e RID: 0x434 acb: 0x00000011 Account: list    Name: Mailing List Manager      Desc: (null)
index: 0x1f RID: 0x436 acb: 0x00000011 Account: irc     Name: ircd      Desc: (null)
index: 0x20 RID: 0x4be acb: 0x00000011 Account: ftp     Name: (null)    Desc: (null)
index: 0x21 RID: 0x4c4 acb: 0x00000011 Account: tomcat55        Name: (null)    Desc: (null)
index: 0x22 RID: 0x3f0 acb: 0x00000011 Account: sync    Name: sync      Desc: (null)
index: 0x23 RID: 0x3fc acb: 0x00000011 Account: uucp    Name: uucp      Desc: (null)

user:[games] rid:[0x3f2]
user:[nobody] rid:[0x1f5]
user:[bind] rid:[0x4ba]
user:[proxy] rid:[0x402]
user:[syslog] rid:[0x4b4]
user:[user] rid:[0xbba]
user:[www-data] rid:[0x42a]
user:[root] rid:[0x3e8]
user:[news] rid:[0x3fa]
user:[postgres] rid:[0x4c0]
user:[bin] rid:[0x3ec]
user:[mail] rid:[0x3f8]
user:[distccd] rid:[0x4c6]
user:[proftpd] rid:[0x4ca]
user:[dhcp] rid:[0x4b2]
user:[daemon] rid:[0x3ea]
user:[sshd] rid:[0x4b8]
user:[man] rid:[0x3f4]
user:[lp] rid:[0x3f6]
user:[mysql] rid:[0x4c2]
user:[gnats] rid:[0x43a]
user:[libuuid] rid:[0x4b0]
user:[backup] rid:[0x42c]
user:[msfadmin] rid:[0xbb8]
user:[telnetd] rid:[0x4c8]
user:[sys] rid:[0x3ee]
user:[klog] rid:[0x4b6]
user:[postfix] rid:[0x4bc]
user:[service] rid:[0xbbc]
user:[list] rid:[0x434]
user:[irc] rid:[0x436]
user:[ftp] rid:[0x4be]
user:[tomcat55] rid:[0x4c4]
user:[sync] rid:[0x3f0]
user:[uucp] rid:[0x3fc]

 ==================================( Share Enumeration on 10.10.10.3 )==================================
                                                                                                                            
                                                                                                                            
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk      
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAME

[+] Attempting to map shares on 10.10.10.3                                                                                  
                                                                                                                            
//10.10.10.3/print$     Mapping: DENIED Listing: N/A Writing: N/A                                                           
//10.10.10.3/tmp        Mapping: OK Listing: OK Writing: N/A
//10.10.10.3/opt        Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:                                                                                              
                                                                                                                            
NT_STATUS_NETWORK_ACCESS_DENIED listing \*                                                                                  
//10.10.10.3/IPC$       Mapping: N/A Listing: N/A Writing: N/A
//10.10.10.3/ADMIN$     Mapping: DENIED Listing: N/A Writing: N/A

 =============================( Password Policy Information for 10.10.10.3 )=============================
                                                                                                                            
                                                                                                                            

[+] Attaching to 10.10.10.3 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

        [+] LAME
        [+] Builtin

[+] Password Info for Domain: LAME

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: Not Set
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set



[+] Retieved partial password policy with rpcclient:                                                                        
                                                                                                                            
                                                                                                                            
Password Complexity: Disabled                                                                                               
Minimum Password Length: 0


 ========================================( Groups on 10.10.10.3 )========================================
                                                                                                                            
                                                                                                                            
[+] Getting builtin groups:                                                                                                 
                                                                                                                            
                                                                                                                            
[+]  Getting builtin group memberships:                                                                                     
                                                                                                                            
                                                                                                                            
[+]  Getting local groups:                                                                                                  
                                                                                                                            
                                                                                                                            
[+]  Getting local group memberships:                                                                                       
                                                                                                                            
                                                                                                                            
[+]  Getting domain groups:                                                                                                 
                                                                                                                            
                                                                                                                            
[+]  Getting domain group memberships:                                                                                      
                                                                                                                            
                                                                                                                            
 ===================( Users on 10.10.10.3 via RID cycling (RIDS: 500-550,1000-1050) )===================
                                                                                                                            
                                                                                                                            
[I] Found new SID:                                                                                                          
S-1-5-21-2446995257-2525374255-2673161615                                                                                   

[+] Enumerating users using SID S-1-5-21-2446995257-2525374255-2673161615 and logon username '', password ''                
                                                                                                                            
S-1-5-21-2446995257-2525374255-2673161615-500 LAME\Administrator (Local User)                                               
S-1-5-21-2446995257-2525374255-2673161615-501 LAME\nobody (Local User)
S-1-5-21-2446995257-2525374255-2673161615-512 LAME\Domain Admins (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-513 LAME\Domain Users (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-514 LAME\Domain Guests (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1000 LAME\root (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1001 LAME\root (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1002 LAME\daemon (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1003 LAME\daemon (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1004 LAME\bin (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1005 LAME\bin (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1006 LAME\sys (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1007 LAME\sys (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1008 LAME\sync (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1009 LAME\adm (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1010 LAME\games (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1011 LAME\tty (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1012 LAME\man (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1013 LAME\disk (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1014 LAME\lp (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1015 LAME\lp (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1016 LAME\mail (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1017 LAME\mail (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1018 LAME\news (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1019 LAME\news (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1020 LAME\uucp (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1021 LAME\uucp (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1025 LAME\man (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1026 LAME\proxy (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1027 LAME\proxy (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1031 LAME\kmem (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1041 LAME\dialout (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1043 LAME\fax (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1045 LAME\voice (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1049 LAME\cdrom (Domain Group)

 ================================( Getting printer info for 10.10.10.3 )================================
                                                                                                                            
No printers returned.                                                                                                       


enum4linux complete on Mon Apr 28 11:00:02 2025
```