# Evil_Twin_Attack project

step 1-
Download Kali to your VM (virtualBox) - https://www.youtube.com/watch?v=V_Payl5FlgQ&t=2s

step 2-
Use network card version 2/3/3.20 - I used version 3.20


It uses hostapd to create the access point, so it is highly configurable. (aka hostapd.conf)

It uses dnsmasq to run the dhcp and dns services. (aka dnsmasq.conf)

It uses apache with help of dnsmasq to launch spoofed webpages as well as captive portals!

Packet sending and receiving is all done via Scapy!

# How it works

* Scan the networks.
* Select network you wish to attack.

Capture handshake (can be used without handshake)
I choose one of several web interfaces tailored for me 
Mounts one FakeAP imitating the original
A DHCP server is created on FakeAP (startAP.sh)
It creates a DNS server to redirect all requests to the Host
The web server with the selected interface is launched
The mechanism is launched to check the validity of the passwords that will be introduced
It deauthentificate all users of the network, hoping to connect to FakeAP and enter the password.
The attack will stop after the correct password checking

GOOD LUCK!
