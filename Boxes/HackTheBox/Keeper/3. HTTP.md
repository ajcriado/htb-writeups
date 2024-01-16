```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Keeper-10.10.11.227]
└─$ whatweb http://10.10.11.227:80/
http://10.10.11.227:80/ [200 OK] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.227], nginx[1.18.0]
                                                                                                                    
┌──(kali㉿kali)-[~/Documents/Boxes/Keeper-10.10.11.227]
└─$ curl http://10.10.11.227:80/                 
<html>
  <body>
    <a href="http://tickets.keeper.htb/rt/">To raise an IT support ticket, please visit tickets.keeper.htb/rt/</a>
  </body>
</html>
```

Add keeper.htb and tickets.keeper.htb to /etc/hosts

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Keeper-10.10.11.227]
└─$ whatweb http://tickets.keeper.htb/
http://tickets.keeper.htb/ [200 OK] Cookies[RT_SID_tickets.keeper.htb.80], Country[RESERVED][ZZ], Email[sales@bestpractical.com], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[RT_SID_tickets.keeper.htb.80], IP[10.10.11.227], PasswordField[pass], Request-Tracker[4.4.4+dfsg-2ubuntu1], Script[text/javascript], Title[Login], X-Frame-Options[DENY], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

Finding some info this is called RT (Request Tracker) for tickets, and the default credentials are root:password . Once we are inside, cheking the menus we find the Admin tab with the Users section, where we find the credentials lnorgaard:Welcome2023! and works with SSH