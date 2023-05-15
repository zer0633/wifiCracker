from scapy.all import *
import sys


wifi = sys.argv[1]
bssid = sys.argv[2]

if wifi == "":
	print("Missing wifi adapter as argument")
	print("run sudo python3 devicefinder.py <wifi adapter> <bssid>")
	sys.exit()
if bssid == "":
	print("Missing bssid as  argument")
	print("run sudo python3 devicefinder.py <wifi adapter> <bssid>")
	sys.exit()



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
