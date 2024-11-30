# Nmap

```bash
# Nmap 7.94SVN scan initiated Tue Nov 26 17:07:24 2024 as: /usr/lib/nmap/nmap -p- --min-rate=10000 --open -oG scans/quick-scan 10.10.33.91
Host: 10.10.33.91 () Status: Up
Host: 10.10.33.91 () Ports: 22/open/tcp//ssh///, 1337/open/tcp//waste/// Ignored State: closed (65533)
# Nmap done at Tue Nov 26 17:07:31 2024 -- 1 IP address (1 host up) scanned in 7.10 seconds
```

# Exploitation

[http://10.10.33.91:1337/](http://10.10.33.91:1337/) - In source code we find note: <!-- Dev Note: Directory naming convention must be hmr_DIRECTORY_NAME -->

Fuzzing: we get [http://10.10.33.91:1337/hmr_logs/error.logs](http://10.10.33.91:1337/hmr_logs/error.logs) and there user tester@hammer.thm

With that email we can break password recovery option at [http://10.10.216.248:1337/reset_password.php](http://10.10.216.248:1337/reset_password.php)
- Catching the recovery request and trying to bruteforce the 4-digit recovery code we get “Rate limit” error ([https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass)](https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass)), so adding `X-Forwared-For` header we can bruteforce the code just by changing the IP at every request. Filtering for “Invalid or expired recovery code” we can get the code

Once inside, we can execute commands but after 5 seconds we are logged out. If we check the command request it has the header `connection: keep-alive` which results in a timeout in the response of 5 seconds. If we remove that header in the request we are not logged out.

We can only execute `ls` command and we find a key. After downloading accesing it to http://10.10.216.248:1337/188ade1.key we get a code, which is a hash that we cracked with [https://www.dcode.fr/cipher-identifier](https://www.dcode.fr/cipher-identifier) (password azerty) but more importantly, it is the key-signature to generate JWT tokens. With [https://jwt.io/](https://jwt.io/) we generate a authorization jwt token with admin role and modify the command request with this new value (just modify authorization token)

![[Pasted image 20241127120441.png]]

![[Pasted image 20241127120726.png]]

And there we have the second flag