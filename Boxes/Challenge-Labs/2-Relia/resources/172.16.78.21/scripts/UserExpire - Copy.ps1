##Sets expiration date and time for Active Directory User.

$user = "RELIA\john.m"
Set-ADAccountExpiration -Identity $user -DateTime '01/08/2030 17:00:00'
Get-ADUser -Identity $user -Properties AccountExpirationDate | Select-Object -Property SamAccountName, AccountExpirationDate
