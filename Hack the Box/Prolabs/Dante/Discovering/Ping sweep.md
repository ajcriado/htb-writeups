```bash
┌──(kali㉿kali)-[~/Documents/Boxes/Dante-Prolab]
└─$ fping -asgq 10.10.110.0/24
10.10.110.2
10.10.110.100

     254 targets
       2 alive
     252 unreachable
       0 unknown addresses

    1008 timeouts (waiting for response)
    1010 ICMP Echos sent
       2 ICMP Echo Replies received
      12 other ICMP received

 46.7 ms (min round trip time)
 49.4 ms (avg round trip time)
 52.1 ms (max round trip time)
        9.217 sec (elapsed real time)
```

### From 10.10.110/100

```bash
root@DANTE-WEB-NIX01:~# for i in $(seq 254); do ping 172.16.1.$i -c1 -W1 & done | grep from
64 bytes from 172.16.1.10: icmp_seq=1 ttl=64 time=0.223 ms
64 bytes from 172.16.1.5: icmp_seq=1 ttl=128 time=0.376 ms
64 bytes from 172.16.1.13: icmp_seq=1 ttl=128 time=0.418 ms
64 bytes from 172.16.1.12: icmp_seq=1 ttl=64 time=0.218 ms
64 bytes from 172.16.1.17: icmp_seq=1 ttl=64 time=0.211 ms
64 bytes from 172.16.1.100: icmp_seq=1 ttl=64 time=0.020 ms
64 bytes from 172.16.1.102: icmp_seq=1 ttl=128 time=0.247 ms
64 bytes from 172.16.1.19: icmp_seq=1 ttl=64 time=0.171 ms
64 bytes from 172.16.1.20: icmp_seq=1 ttl=128 time=0.615 ms
64 bytes from 172.16.1.101: icmp_seq=1 ttl=128 time=0.422 ms
```