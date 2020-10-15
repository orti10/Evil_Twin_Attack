#!/bin/sh
airmon-ng check kill
ifconfig wlan1 10.0.0.1 netmask 255.255.255.0
route add default gw 10.0.0.1
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -P FORWARD ACCEPT
dnsmasq -C /root/matala/dnsmasq.conf
hostapd /root/matala/hostapd.conf -B
service apache2 start
