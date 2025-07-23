### Mapping A Network (with multiple tools) :
#### Wireshark :
- Run wireshark as admin (`sudo wireshark`)
- You will have a menu with some options, select your iface
#### F-Ping
- it's a tool to ping multiple hosts at one time
- `fping -I [netInterface] -g [your ip but with 0 instead of the last numbers]/24` 
#### ARP scan 
- network discovery you can use if hosts doesn't respond to ICMP pakets.
- `-I [netInterface] -g [your ip but with 0 instead of the last numbers]/24` 
#### ZENMap 
- Graphical nmap version, very good to vizualise network layout
### Useful tips : 
#### No ports detected ? 
- simply add `-sU` to your Nmap to check UDP ports, if no ports are detected again consider adding `-Pn` to both UDP & TCP.

[couldnt recover the rest of the notes, unfortunately]
