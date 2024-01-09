---

---
#### ++ INFO ++
-> After login in `9999/admin` with credentials found in JS (`admin:superduperlooperpassword_lol`) we found a strange encrypted code in `9999/admin/success.html` and we can decode it **[here](https://www.dcode.fr/ook-language)**
-> In `/asdiSIAJJ0QWE9JAS` we found a b64 code, and after decode it and save it with the comand `file` we discovered a zip file. After crack it with zip2john and john we found the password `password`
-> In the zip file found we found a hex code in `index.php`, so we can reverse it with `xxd` and we get a b64 code. Decode it (removing whitespaces) and we get a brainfuck code which says `idkwhatispass`
	`cat index.php | xxd -r -p > b64-hex-decoded.txt`
	`cat b64-hex-decoded.txt | tr -d "\n\r" > b64-no-whitespaces.txt`
	`cat b64-no-whitespaces.txt | base64 -d`
	**[brainfuck](https://www.dcode.fr/brainfuck-language)**
#### ++ USERS ++
	Name Surname

#### ++ CREDENTIALS ++
	admin:superduperlooperpassword_lol (Found in 9999/admin/ JS console)
	admin:imnothuman (Found in 9999/backup)
	admin:idkwhatispass (PlaySMS login)
	
#### ++ PlaySMS CVE-2017-9101 vuln ++
	Abuse it with admin:idkwhatispass and multi/http/playsms_uploadcsv_exec metasploit module

#### ++ Priv Esc ++
	We need to abuse Buffer Overflow and is out of scope for CPTS