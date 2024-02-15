##Sets expiration date and time for Active Directory User.

$user = "RELIA\john.m"
$SecureString = ConvertTo-SecureString "YouWillNeverTakeMyTractor!1922" -AsPlainText -Force
$creddent = New-Object System.Management.Automation.PSCredential($user, $SecureString)
Set-ADAccountExpiration -Identity $user -Credential $creddent -DateTime '17/01/2030 17:00:00'
Get-ADUser -Identity $user -Properties AccountExpirationDate | Select-Object -Property SamAccountName, AccountExpirationDate
