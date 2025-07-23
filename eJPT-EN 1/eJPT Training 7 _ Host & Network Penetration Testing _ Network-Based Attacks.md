# Learning Objectives :
![[Pasted image 20230924165145.png]]
![[Pasted image 20230924165202.png]]
# Course :
## Network Based Attacks 
![[Pasted image 20230924165359.png]]
![[Pasted image 20230924165447.png]]
## Tshark :
### What does it do ?
Basically it's a CLI of Wireshark

### Usage :
- Use `tshark -D` to display interfaces that you can listen on
- Set the `-i [interface]` to the interface you will need to use
- Set the `-r [filename].pcap` to read a file
- Set the `-Y "[Filters]"` Here will go wireshark filters
- Use `man tshark` for more detailed usage 

## ARP poisoning :
### What does it do ?
- It can help to intercept trafic that we are not meant to.

### Usage : 
- Check the host you can spy on with `nmap [your.ip.addr.0]/24` 
- Before any operation you should check the Traffic you can see with Wireshark.
- To see traffic between machines you can pretend to be someone else
- First enable IP Forwarding with the following command : ``echo 1 > /proc/sys/net/ipv4/ip_forward`` 
- To spoof (to pretend that you are) an IP you can basically use a tool named `ARPSpoof` and the following command : `arpspoof -i [interface] -t [vcip] -r [gateway IP]
	  I know it's not clear but imagine that .31 is talking with .37 on Telnet, 
	  .31 uses telnet, and is the victim
	  .37 has telnet, and is the gateway
	  With that command you can see what 31 is sending to 37.
- ![[Pasted image 20230927123951.png]]
## Advanced Wifi Filtering (With Tshark again.) :
- All of the above should be put in `-Y '[there]'` because it's only filters.
- Certainly, here are the answers with the commands:

In the context of Network name = "MyWiFiNetwork" and BSSID = "00:11:22:33:44:55":

Questions:

Set A:

1. Which command can be used to show only WiFi traffic?
   
   ```bash
   tshark -r your_capture.pcap -Y "wlan"
   ```

   Replace `your_capture.pcap` with your PCAP file.

2. Which command can be used only to view the deauthentication packets?

   ```bash
   tshark -r your_capture.pcap -Y "wlan.fc.type_subtype == 0x0c"
   ```

   Replace `your_capture.pcap` with your PCAP file.

3. Which command can be used to only display WPA handshake packets?

   ```bash
   tshark -r your_capture.pcap -Y "wlan_mgt.fixed.capabilities.ess == 1 and wlan_mgt.fixed.capabilities.privacy == 1 and wlan.fc.type_subtype == 0x08"
   ```

   Replace `your_capture.pcap` with your PCAP file.

4. Which command can be used to only print the SSID and BSSID values for all beacon frames?

   ```bash
   tshark -r your_capture.pcap -Y "wlan.fc.type_subtype == 0x08" -T fields -e wlan.ssid -e wlan.bssid
   ```

   Replace `your_capture.pcap` with your PCAP file.

Set B:

1. What is the BSSID of SSID "MyWiFiNetwork"?

   This question can be answered using a tool like `airodump-ng`:

   ```bash
   airodump-ng your_capture.pcap
   ```

   Replace `your_capture.pcap` with your PCAP file. Look for the "BSSID" associated with the "MyWiFiNetwork" SSID in the output.

2. SSID "MyWiFiNetwork" is operating on which channel?

   This can also be determined from the `airodump-ng` output. Look for the "CH" (channel) value associated with the "MyWiFiNetwork" SSID.

3. Which two devices received the deauth messages? State the MAC addresses of both.

   You can use a Wireshark filter for deauthentication packets:

   ```bash
   tshark -r your_capture.pcap -Y "wlan.fc.type_subtype == 0x0c"
   ```

![[Pasted image 20230927150604.png]]![[Pasted image 20230927150613.png]]
