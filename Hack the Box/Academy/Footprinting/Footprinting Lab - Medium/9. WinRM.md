Alex credentials:
```bash
xfreerdp /u:alex /p:"lol123!mD" /v:10.129.99.224
zsh: event not found: mD
```

Try to escape the ! character
```bash
xfreerdp /u:alex /p:"lol123!mD" /v:10.129.99.224
```

And it connects. In the desktop we can see the Microsoft SQL Server Management Studio, we have to open it and it will prompt the login window with the sa credentials.
![[Pasted image 20230704093200.png]]

If we introduce the password and if we try every option too. If we use the Azure Active Directory Password it throws a message saying that the login was successful but the certificate is not trusted
![[Pasted image 20230704094024.png]]

Click in options and under connection properties check "Trust server certificate" and try to login again. But it doesn't work.

If we dive in the File explorer, try to access to the Administrator folder we can go in with the sa password.

So we close the alex WinRM session and try again with the administrator:87N1ns@slls83 credentials and we are in with the administrator account
```bash
xfreerdp /u:administrator /p:"87N1ns@slls83" /v:10.129.99.224
```

Open the Microsoft SQL Server Management Studio (with Windows credentials option). Here we can query the found table and there it is our HTB credentials
![[Pasted image 20230704102943.png]]

