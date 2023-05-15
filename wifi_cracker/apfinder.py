import sys
import os
from scapy.all import *


if len(sys.argv) <= 1:
    print("Missing wifi adapter name as argument")
    print("Run sudo python3 apfinder.py <wifi adapter>")
    sys.exit()
else:
    wifi = sys.argv[1]
    print("Wifi adapter:", wifi)

# put the wireless interface into monitor mode
os.system("sudo ifconfig "+wifi+" down")
os.system("sudo iwconfig "+wifi+" mode monitor")
os.system("sudo ifconfig "+wifi+" up")

print("Monitor mode enabled. Starting to sniff...")
# define a packet handler function
def handler(packet):
	with open("log.txt",'a')as f:
		if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
    	# Extract the SSID 
			ssid = packet[Dot11Elt].info.decode()
			bssid = packet[Dot11].addr2
			channel = ord(packet[Dot11Elt:3].info)
			f.write(ssid)
			with open("log.txt", 'r') as f:
				l = f.readlines()
				if ssid in ''.join(l):
					pass
				else:
    	    	# Print out the network information
					print(f"Channel:{channel}  SSID: {ssid}  BSSID: {bssid}")
# Start sniffing wireless packets with the callback function
sniff(iface=wifi, prn=handler)
