#### ++ INFO ++
-> SSL certificate
	`admin@nineveh.htb`
-> Code comment in `80/department/login.php`
	`<!-- @admin! MySQL is been installed.. please fix the login page! ~amrois -->`
-> Notes inside `80/department`
	`- Have you fixed the login page yet! hardcoded username and password is really bad idea!`
	`- check your serect folder to get in! figure it out! this is your challenge`
	`- Improve the db interface.`
	`~amrois`
	
#### ++ USERS ++
	admin

#### ++ CREDENTIALS ++
	admin:1q2w3e4r5t (80/department/login.php)
	password123 (443/db/index.php)

#### ++ HOSTS (Check with Aquatone if numerous) ++
	`http://nineveh.htb/`
	`https://nineveh.htb/`
	
#### ++ Weak credentials for admin user in `80/department/login.php` ++
	After brute forcing the http://nineveh.htb/department/login.php login form we found weak credentials for admin user

#### ++ LFI in `80/department/manage.php`++
	We can abuse notes parameter in manage.php page by pointing a file, but the file must contains "ninevehNotes" string in its filename

#### ++ Weak credentials in `443/db/index.php` ++
	After brute forcing the https://nineveh.htb/db/index.php login form we found weak credentials

#### ++ RCE by injecting php code in phpLiteAdmin (443) and reading it with LFI (80) ++
	With 24044 exploit (exploitdb) we create a database called ninevehNotes.php and inject php code
	Now, we can execute the code through LFI by accessing http://nineveh.htb/department/manage.php?notes=/var/tmp/ninevehNotes.php

#### ++ Priv Esc ++
	With pspy64 we find a cronjob executing chkrootkit as user and we found exploit 33899 (exploitdb)
	Create a update file in /tmp with python reverse shell (do not forget the bash header) and get a shell as root