##Sets expiration date and time for Active Directory User.

$user = read-Host 'Whats the AD username to set to expire:'
Set-ADAccountExpiration -Identity $user -DateTime '01/01/2030 17:00:00'
Get-ADUser -Identity $user -Properties AccountExpirationDate | Select-Object -Property SamAccountName, AccountExpirationDate
