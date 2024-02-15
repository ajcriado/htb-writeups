Function workaround-36934 {
param (
[Parameter(Mandatory=$true)]
[string]$computername,
[string]$credential = 'contoso\username') #default credential you'll need to change it for yourself

    invoke-command -ComputerName $computername -credential $credential -ScriptBlock{
    #changes permisions
    icacls $env:windir\system32\config\*.* /inheritance:e
     
    # deletes shadow copies that existed before the permission change
    vssadmin delete shadows /for=C: /Quiet # change the system drive to a different one if needed.
    
    # creates a new shadow copy
    wmic shadowcopy call create Volume="C:\" 2>&1 | out-null
   } 
   write-host 'Note: As long as you see "Failed Procesing 0 files" you can ignore "Error: Either the speciified volume was not found or it is not a local volume" ' -ForegroundColor Cyan
   write-host "you can run a sanity check by using" -NoNewline
   write-host " PS:> vssadmin list shadows" -ForegroundColor Yellow 
   <#
        .NOTES
        Version:       1.0
        Author:        shadexic
        Created on:    2021-07-22
        notes:         workaround steps as provided by Microsoft as of July 22 2021
                       for CVE-2021-36934 system32 local priviledge escalation
        .SYNOPSIS
        Remote Mitigation for CVE-2021-36934 (system32 local privilege elevation exploit).
        .DESCRIPTION
        Designed to perform the steps provided on July 22 2021 for workaround.
        Step 1 Restricts access to the contents of %windir%\system32\config.
        Step 2 Deletes shadow Copies from machine.
        Step 3 Creates new shadow copy of the C drive.
        Step 4 ignores "error" returned by step 3, powershell interpets feedback from this command.
        as an error so it is discarded, Shadow copies can be confirmed by running the following.
        PS> vssadmin list shadows.
        (note: doesn't work in ise, but does in elevated powershell console)
        .PARAMETER computername
        Specifies the remote computer name.
      
        .PARAMETER credential
        Specifies the credential to use (note: you'll need the domain\).
        you can default the credential to use by modifying line 5 to suit your needs.
        .INPUTS
        None. You cannot pipe objects to workaround-36934
        .OUTPUTS
        System.String. searchlog returns a string with the result of the actions and discards (pipes to null) the values returned that powershell mistakenly thinks are errors.
        .EXAMPLE
        PS> workaround-36934 shadexicdesktop contoso\shadexic
        
        .LINK
        https://github.com/shadexic/sysadmin-scripts/tree/main/powershell/cve-solutions
        .LINK
        https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934
    #>
   }
