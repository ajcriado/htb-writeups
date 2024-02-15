#Requires -Version 2.0

<#
.SYNOPSIS
 Get BitLocker Recovery Information from Active Directory.
 Generates a CSV file with computer names and BitLocker Recovery Keys.

.DESCRIPTION
 Get BitLocker Recovery Information from Active Directory.
 Generates a CSV file with computer names and BitLocker Recovery Keys:
    ComputerName;OperatingSystem;Date;Time;GMT;PasswordID;RecoveryPassword;DistinguishedName

 Requirement of the script:
    - Active Directory PowerShell Module
    - Needed rights to view AD BitLocker Recovery Info

 
 Usage:
    .\Get-ADComputers-BitLockerInfo.ps1
    .\Get-ADComputers-BitLockerInfo.ps1 -OU "OU=Computers,OU=IT Department,DC=myDomain,DC=com"

 
 Recommendation is to run this script as a schedule task to have backup your BitLocker Recovery keys

 In Section Initialisations you may set default value:
 to set default value for OU
    [string]$OU =
 to set default name for a CSV file
    [string]$LogFileName = 
 to set default path for a CSV file
    [string]$LogFilePath = 


.PARAMETER OU
    Optional parameter to narrow the scope of the script

.PARAMETER LogFilePath
    Optional parameter to set path for log files

    Example: -LogFilePath "C:\Scripts"

.PARAMETER LogFileName
    Optional parameter to set name for log files


.NOTES
   File Name  : Get-ADComputers-BitLockerInfo.ps1
   Version    : 2.0
   Date       : 2018.07.03
   Author     : Andriy Zarevych


.EXAMPLE
   .\Get-ADComputers-BitLockerInfo.ps1

   Description
   -----------
   Generates a CSV file with computer names and BitLocker Recovery Keys
   
.EXAMPLE
   .\Get-ADComputers-BitLockerInfo.ps1 -OU "OU=Computers,OU=IT Department,DC=myDomain,DC=com"

   Description
   -----------
   Generates a CSV file with computer names and BitLocker Recovery Keys for computers in targed OU

.EXAMPLE
   .\Get-ADComputers-BitLockerInfo.ps1 -OU "OU=Computers,OU=IT Department,DC=myDomain,DC=com" -LogFilePath "C:\Scripts" -LogFileName "BitlockerInfo.csv"

   Description
   -----------
   Generates a CSV file with specific name and path

#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

[CmdletBinding()]

    Param(
    [Parameter(Mandatory=$false, HelpMessage="Enter OU, example: OU=Computers,OU=ITDep,DC=contoso,DC=com", ValueFromPipelineByPropertyName=$true)]    
    [string]$OU,
    [Parameter(Mandatory=$false, HelpMessage="Enter path for log file, example: C:\Scripts", ValueFromPipelineByPropertyName=$true)]    
    [string]$LogFilePath = ".\",
    [Parameter(Mandatory=$false, HelpMessage="Enter log file Name", ValueFromPipelineByPropertyName=$true)]    
    [string]$LogFileName = "BitLockerInfo_$(Get-Date -f 'yyyy-MM-dd').csv"
    )

#----------------------------------------------------------[Declarations]----------------------------------------------------------

Import-Module ActiveDirectory

#To separating fields for report
$strDelimiter = ";"

if (-Not (Test-Path -PathType Container $LogFilePath)){
    $LogFilePath = New-Item -ItemType Directory -Force -Path $LogFilePath
}

if ($LogFilePath.Substring($LogFilePath.Length-1) -eq "\" -or $LogFilePath.Substring($LogFilePath.Length-1) -eq "/"){
   
}
else {
    $LogFilePath = $LogFilePath + "\"
}

$LogFile = $LogFilePath + $LogFileName

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#Report file $LogFile

if (Test-Path $LogFile){
    #Remove-Item $LogFile
    Clear-Content $LogFile
}
else {
    $LogFile = New-Item -Path $LogFilePath -Name $LogFileName -ItemType File
}


#

write-host
write-host "Script start" $(Get-Date)
write-host

#Set scope
#Get computers info
if ($OU -ne "") {
    Write-Host "Organizational Unit:" $OU
    $Computers = Get-ADComputer -Filter 'ObjectClass -eq "computer"' -Property * -SearchBase $OU
    
}
else {
    Write-Host "Domain:" $env:userdnsdomain
    $Computers = Get-ADComputer -Filter 'ObjectClass -eq "computer"' -Property *
}

write-host "Report File Path:" $LogFile

#Write report header
$strToReport = "ComputerName" + $strDelimiter + "OperatingSystem" + $strDelimiter + "Date" + $strDelimiter + "Time" + $strDelimiter + "GMT" + $strDelimiter + "PasswordID" + $strDelimiter + "RecoveryPassword" + $strDelimiter + "DistinguishedName"
Add-Content $LogFile $strToReport

#Get BitLocker Recovery Info
#Write report
foreach ($Computer in $Computers) {

    $BitLockerObjects=(Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $Computer.DistinguishedName -Properties msFVE-RecoveryPassword)

    foreach ($BitLockerObject in $BitLockerObjects) {
    
        #The name of the BitLocker recovery object incorporates a globally unique identifier (GUID) and date and time information, 
        #for a fixed length of 63 characters. The form is: <Object Creation Date and Time><Recovery GUID>
        #For example:
        #2005-09-30T17:08:23-08:00{063EA4E1-220C-4293-BA01-4754620A96E7}
        #$BitLockerObject.Name
        $strComputerDate = $BitLockerObject.Name.Substring(0,10)
        $strComputerTime = $BitLockerObject.Name.Substring(11,8)
        $strComputerGMT = $BitLockerObject.Name.Substring(19,6)
        $strComputerPasswordID = $BitLockerObject.Name.Substring(26,36)
        $strComputerRecoveryPassword = $BitLockerObject.'msFVE-RecoveryPassword'
    
        #$strToReport = $Computer.Name + $delimiter + $Computer.OperatingSystem + $delimiter + $strComputerDate + $delimiter + $strComputerTime + $delimiter + $strComputerGMT + $delimiter + $strComputerPasswordID + $delimiter + $strComputerRecoveryPassword + $delimiter + $Computer + $delimiter + $BitLockerObject
        $strToReport = $Computer.Name + $strDelimiter + $Computer.OperatingSystem + $strDelimiter + $strComputerDate + $strDelimiter + $strComputerTime + $strDelimiter + $strComputerGMT + $strDelimiter + $strComputerPasswordID + $strDelimiter + $strComputerRecoveryPassword + $strDelimiter + $Computer.DistinguishedName
        
        Add-Content $LogFile $strToReport
    }

}

write-host
write-host "Script end" $(Get-Date)
write-host
