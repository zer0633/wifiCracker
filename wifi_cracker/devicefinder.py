from scapy.all import *
import sys



if len(sys.argv) <= 2:
	print("Missing wifi adapter and access point bssid as arguments")
	print("Run sudo python3 devicefinder.py <wifi adapter> <access point bssid>")
	sys.exit()
else:
	wifi = sys.argv[1]
	bssid = sys.argv[2]



devices = set()

def handler(packet):
	with open("devices.txt",'a')as f:
		if packet.haslayer(Dot11) and packet.addr2 == bssid:
			devices.add(packet.addr1)
			f.write(packet.addr1)
			with open("devices.txt",'r')as f:
				l = f.readlines()
				if packet.addr1 in ''.join(l):
					pass
				else:
					print(f"Connected Device:{packet.addr1}")

sniff(iface=wifi, prn=handler)
