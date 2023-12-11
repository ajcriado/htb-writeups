List shares with alex credentials
```bash
smbclient -U alex -L //10.129.151.227

Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        devshare        Disk      
        IPC$            IPC       Remote IPC
        Users           Disk      
```

Connect to devshare
```bash
smbclient -U alex //10.129.151.227/devshare
ls
  .                                   D        0  Wed Nov 10 17:12:22 2021
  ..                                  D        0  Wed Nov 10 17:12:22 2021
  important.txt                       A       16  Wed Nov 10 17:12:55 2021

get important.txt
*Error opening local file important.txt*
```

And try to download important.txt but we don't have enough access. Connect to Users
```bash
smbclient -U alex //10.129.151.227/Users
ls
  .                                  DR        0  Thu Nov 11 01:25:55 2021
  ..                                 DR        0  Thu Nov 11 01:25:55 2021
  alex                                D        0  Thu Nov 11 01:25:55 2021
  Default                           DHR        0  Tue Dec 15 11:32:11 2020
  desktop.ini                       AHS      174  Sat Sep 15 09:16:48 2018
  
cd alex
ls
  .                                   D        0  Thu Nov 11 01:25:55 2021
  ..                                  D        0  Thu Nov 11 01:25:55 2021
  3D Objects                         DR        0  Wed Nov 10 15:19:25 2021
  AppData                            DH        0  Wed Nov 10 15:19:22 2021
  Contacts                           DR        0  Wed Nov 10 15:19:25 2021
  Desktop                            DR        0  Thu Nov 11 00:34:44 2021
  devshare                            D        0  Wed Nov 10 17:12:22 2021
  Documents                          DR        0  Thu Nov 11 01:25:27 2021
  Downloads                          DR        0  Wed Nov 10 15:19:25 2021
  Favorites                          DR        0  Wed Nov 10 15:19:25 2021
  Links                              DR        0  Wed Nov 10 15:19:26 2021
  Music                              DR        0  Wed Nov 10 15:19:25 2021
  NTUSER.DAT                        AHn  3670016  Wed Nov 17 12:45:40 2021
  ntuser.dat.LOG1                   AHS   971776  Wed Nov 10 15:19:21 2021
  ntuser.dat.LOG2                   AHS   458752  Wed Nov 10 15:19:21 2021
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf    AHS    65536  Wed Nov 10 15:20:10 2021
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Wed Nov 10 15:19:21 2021
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Wed Nov 10 15:19:21 2021
  ntuser.ini                         HS       20  Wed Nov 10 15:19:22 2021
  Pictures                           DR        0  Wed Nov 10 15:19:25 2021
  Saved Games                        DR        0  Wed Nov 10 15:19:26 2021
  Searches                           DR        0  Wed Nov 10 15:19:26 2021
  TechSupport                         D        0  Thu Nov 11 01:09:49 2021
  Videos                             DR        0  Wed Nov 10 15:19:25 2021

cd devshare
ls
  .                                   D        0  Wed Nov 10 17:12:22 2021
  ..                                  D        0  Wed Nov 10 17:12:22 2021
  important.txt                       A       16  Wed Nov 10 17:12:55 2021

get important.txt

getting file \alex\devshare\important.txt of size 16 as important.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

And we have retrieved the important.txt file, which contains credentials sa:87N1ns@slls83

Login in SMB with sa credentials doesn't work