import os
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11, RadioTap, Dot11Deauth
from scapy.all import *

# MAC address of AP to defend
ap_to_defense = ""

# Counter to count the deauthentication packets received
counter = 0

# A list of all AP MACs scanned
ap_mac_scanned = {}

def filter_packets(pkt):
    global ap_mac_scanned
    if pkt.type == 0 and pkt.subtype == 8:
        if pkt.addr2 not in ap_mac_scanned:
            ap_mac_scanned[pkt.addr2] = pkt.addr2
            print(len(ap_mac_scanned), '     %s     %s ' % (pkt.addr2, pkt.info))

# A function that finds the number of deauthentication packets sent to chosen network:
def defense(pkt):
    global ap_to_defense
    client = pkt[Dot11].addr3
    global counter
    # pkt type 0 & subtype 12 is deauthentication pkt.
    if(pkt.type == 0):
        if(pkt.subtype == 12):
            if(client == ap_to_defense):
                counter+=1
    # If we get more than 50 deauthentication packets
    if(counter > 50):
        print("YOU ARE UNDER DEAUTHENTICATION ATTACK !!!")


def main():
# Code to switch to monitor mode (equals to airmon-ng)
    os.system('iwconfig')
    networkCard = raw_input("Enter the name of the network card you want to switch to monitor mode: \n")
    os.system('sudo ifconfig ' + networkCard + ' down')
    os.system('sudo iwconfig ' + networkCard + ' mode monitor')
    os.system('sudo ifconfig ' + networkCard + ' up')
    os.system('iwconfig')
    print("Scanning for access points, please wait... or press CTRL+C to stop scanning")
    print("index         MAC            SSID")
    sniff(iface=networkCard, prn=filter_packets)
    ap_to_defense = raw_input('Please enter the BSSID address (mac-address) to defense: ')
    sniff(iface=networkCard, prn=defense)

main()
