#!/bin/bash

# The following is a Shell script to deploy a fully working router with a vpn client. 

# Author: omrsangx

if [ "$EUID" -ne 0 ]; then
    echo "You must run the script as root"
    exit
fi

echo "*******************************************************************"
echo "************** Setting the environment ****************************" | tee -a $INSTALLATION_LOG 
echo "*******************************************************************"

CURRENT_DATE=$(date +%Y_%m_%d_%H_%M)
INSTALLATION_LOG="/tmp/router_wireguard_setup_$CURRENT_DATE.log"
BACKUP_CONF_DIR="/tmp/backup_conf_files_$CURRENT_DATE"
ERROR_CODE=0
# ERROR_CODE=$(echo $?)

if [ ! -d BACKUP_CONF_FILES ] ; then
    mkdir $BACKUP_CONF_DIR
fi

echo "*******************************************************************"
echo "************** Netplan configuration ******************************" 
echo "*******************************************************************"

WIFI_NAME="WIFI_NAME_GOES_HERE"
WIFI_PASSWORD="WIFI_PASSWORD_GOES_HERE"

mv /etc/netplan/* $BACKUP_CONF_DIR
cat << EOLNETPLAN > /etc/netplan/01-network-manager-all.yaml
# netplan network configuration 
network:
    ethernets:
        eth0:
            dhcp4: false
            dhcp6: false
            addresses: [192.168.2.1/24]
            nameservers:
                    addresses: [1.1.1.1]
            #optional: true

    wifis:
        wlan0:
            access-points:
                 "$WIFI_NAME":
                    password: "$WIFI_PASSWORD"
            dhcp4: false
            dhcp6: false
            optional: true
            addresses: [192.168.5.166/24]
            #gateway4: 192.168.5.1
            routes:
              - to: default
                via: 192.168.5.1
            nameservers:
                addresses: [1.1.1.1, 8.8.8.8]

    version: 2 
    renderer: networkd
    
EOLNETPLAN

netplan apply | tee -a $INSTALLATION_LOG
    
echo -e "\n"    
echo "Network configuration completd - press Enter to continue or Ctrl + c to terminate......"
read

echo "Network configuration"
    ip ad 

echo "*******************************************************************"
echo "************** Installing system updates **************************" | tee -a $INSTALLATION_LOG
echo "*******************************************************************"
    apt update -y | tee -a $INSTALLATION_LOG
    apt upgrade -y | tee -a $INSTALLATION_LOG
    echo -e "\n"
    echo "Updates Installed" | tee -a $INSTALLATION_LOG

echo "*******************************************************************"
echo "************** Installing needed packages *************************" | tee -a $INSTALLATION_LOG
echo "*******************************************************************"
    # ****** Installing utility tools ******
    apt install vim -y
    apt install wget -y
    apt install curl -y
    apt install nmap -y
    
    # ****** Installing DHCP server and iptables packages ******
    apt install isc-dhcp-server -y | tee -a $INSTALLATION_LOG
    apt install iptables-persistent -y | tee -a $INSTALLATION_LOG
    apt install iptables -y | tee -a $INSTALLATION_LOG
    
    # ****** Installing Wireguard packages ******
    apt install wireguard -y | tee -a $INSTALLATION_LOG
    
    echo -e "\n"
    echo "Packages installed"
    echo "Press Enter to continue or Ctrl + C to terminate......"
    read
    
echo "*******************************************************************"
echo "************** DHCP Server Configuration **************************" | tee -a $INSTALLATION_LOG
echo "*******************************************************************"

ROUTER_LAN_INTERFACE="eth0"

DEVICE_MAC_ADDRESS=$(ip link show $ROUTER_LAN_INTERFACE | grep -i link | awk -F" " '{print $2}')

mv /etc/default/isc-dhcp-server $BACKUP_CONF_DIR
touch /etc/default/isc-dhcp-server

# Binding the DHCP server to an interface:
echo "INTERFACESv4=\"$ROUTER_LAN_INTERFACE\"" >> /etc/default/isc-dhcp-server
echo "INTERFACESv6=\"\"" >> /etc/default/isc-dhcp-server

cat /etc/default/isc-dhcp-server
echo -e "\n"

mv /etc/dhcp/dhcpd.conf $BACKUP_CONF_DIR
touch /etc/dhcp/dhcpd.conf

cat << EOLDHCP > /etc/dhcp/dhcpd.conf
#option domain-name "example.org";
option domain-name-servers 8.8.8.8, 1.1.1.1;
ddns-update-style none;
default-lease-time 600;
max-lease-time 7200;
#log-facility local7;
authoritative;

subnet 192.168.2.0 netmask 255.255.255.0 {
  interface $ROUTER_LAN_INTERFACE;
  range 192.168.2.100 192.168.2.200;
  option subnet-mask 255.255.255.0;
  option broadcast-address 192.168.2.255;
  option routers 192.168.2.1;
}

host server {
  hardware ethernet $DEVICE_MAC_ADDRESS;
  fixed-address 192.168.2.1;
}

EOLDHCP

echo "Checking configuration"
cat /etc/dhcp/dhcpd.conf

echo "Press enter to continue........"
read

systemctl enable isc-dhcp-server
systemctl restart isc-dhcp-server
systemctl status isc-dhcp-server

# Troubleshooting dhcp server: /var/log/syslog 
echo -e "\n"
echo " DHCP setup completed - press enter to continue or Ctrl + c to terminate......"
read

systemctl status isc-dhcp-server

echo "*******************************************************************"
echo "************** ipv4.ip_forward configuration **********************" | tee -a $INSTALLATION_LOG
echo "*******************************************************************"

mv /etc/sysctl.conf $BACKUP_CONF_DIR
touch /etc/sysctl.conf

echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p 

echo -e "\n"
echo "Press enter to continue........"
read

echo "*******************************************************************"
echo "************** Firewall configuration *****************************" | tee -a $INSTALLATION_LOG
echo "*******************************************************************"

WAN_INTERFACE="wlan0"
LAN_INTERFACE="eth0"
WIREGUARD_INTERFACE="wg0"

echo "****** Disabling ufw ******"
ufw disable
systemctl stop ufw
systemctl disable ufw

echo "****** Disabling firewalld ******"
systemctl stop firewalld
systemctl disable firewalld

echo -e "\n"
echo "Press enter to continue........"
read 

mv /etc/iptables/rules.v4 $BACKUP_CONF_DIR
touch /etc/iptables/rules.v4

cat << EOLFIREWALL > /etc/iptables/rules.v4
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE
COMMIT

*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# $WAN_INTERFACE is the WAN
# $LAN_INTERFACE is the LAN

# INPUT
-A INPUT -j LOG --log-level 4 --log-prefix " iptables_log "

# Accept ssh connection into the router (add this one if you need it):
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT

-A INPUT -i $WAN_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Drop invalid traffic:
-A INPUT -m conntrack --ctstate INVALID -j DROP

# Drop all other inbound traffic
-A INPUT -j DROP

# FORWARD
-A FORWARD -j LOG --log-level 4 --log-prefix " iptables_log "

# To prevent any traffic from leaving the local network if it is not through the vpn, this should be deleted
-A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT 
-A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Forwarding internal/local router's traffic ($LAN_INTERFACE) through the WireGuard VPN (through $WIREGUARD_INTERFACE interface)
-A FORWARD -i $LAN_INTERFACE -o $WIREGUARD_INTERFACE -j ACCEPT
-A FORWARD -i $WIREGUARD_INTERFACE -o $LAN_INTERFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# drop all other forwarded traffic
-A FORWARD -j DROP

# OUTPUT
-A OUTPUT -j LOG --log-level 4 --log-prefix " iptables_log "

COMMIT

EOLFIREWALL

cat /etc/iptables/rules.v4

echo -e "\n"
echo "Press enter to continue........"
read

iptables-restore /etc/iptables/rules.v4 | tee -a $INSTALLATION_LOG
iptables-save > saved_iptables_rules.txt

systemctl enable iptables | tee -a $INSTALLATION_LOG
systemctl start iptables | tee -a  $INSTALLATION_LOG

iptables -L -v --line-numbers | tee -a $INSTALLATION_LOG

echo -e "\n"
echo "Firewall configuration completed - press enter to continue or Ctrl + c to terminate......"
read

echo "*******************************************************************"
echo "************** Wireguard - VPN Client configuration ***************" | tee -a $INSTALLATION_LOG 
echo "*******************************************************************"

if [ -d /etc/wireguard ] ; then
    mv /etc/wireguard/* $BACKUP_CONF_DIR
else 
    mkdir /etc/wireguard
fi

cd /etc/wireguard
umask 077

wg genkey | tee -a /etc/wireguard/client_privatekey | wg pubkey > /etc/wireguard/client_publickey

WIREGUARD_INTERFACE="wg0"
CLIENT_PRIVATE_KEY=$(cat /etc/wireguard/client_privatekey)
CLIENT_PUBLIC_KEY=$(cat /etc/wireguard/client_publickey)
# WIREGUARD_SERVER_PUBKEY=""
# WIREGUARD_VPN_SERVER_IP=""

echo "Enter your WireGuard's server public key: "
read WIREGUARD_SERVER_PUBKEY
echo -e "\n"

echo "Enter your WireGuard's server IP address: "
read WIREGUARD_VPN_SERVER_IP
echo -e "\n"

echo "Enter your WireGuard's server port number: "
read WIREGUARD_VPN_SERVER_PORT
echo -e "\n"

cat << EOLWIREGUARD > /etc/wireguard/wg0.conf 
[Interface]
Address = 192.168.6.4/24
ListenPort = 50825
PrivateKey = $CLIENT_PRIVATE_KEY

[Peer]
# Remote WireGuard server's public key 
PublicKey = $WIREGUARD_SERVER_PUBKEY
# Remote WireGuard server's IP address and port number
Endpoint =  $WIREGUARD_VPN_SERVER_IP:$WIREGUARD_VPN_SERVER_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 21

EOLWIREGUARD

chmod 600 /etc/wireguard/*

cat /etc/wireguard/wg0.conf 

echo -e "\n"
echo "****************************************************************************************************"
echo "    ++++++++ Your WireGuard's public key is: $CLIENT_PUBLIC_KEY ++++++++" | tee -a $INSTALLATION_LOG 
echo "****************************************************************************************************"
echo -e "\n"

echo "Press Enter to continue with the configuration or Ctrl + c to terminate"
read

systemctl enable wg-quick@wg0 | tee -a $INSTALLATION_LOG
systemctl start wg-quick@wg0 | tee -a $INSTALLATION_LOG

echo -e "\n"
echo "Press Enter to start the WireGuard's VPN connection or Ctrl + c to terminate"
read

wg-quick up wg0 | tee -a $INSTALLATION_LOG

echo "$(wg)" | tee -a $INSTALLATION_LOG
echo -e "\n"
echo "$(curl --interface $WIREGUARD_INTERFACE -s https://icanhazip.com)" | tee -a $INSTALLATION_LOG
echo -e "\n"

echo "Review the installation log at $INSTALLATION_LOG"
echo "Preview configuration files were backup to $BACKUP_CONF_DIR"

# Rebooting the server
echo "The router configuration completed - Press Enter to reboot the server or Ctrl + c to terminate"
read

reboot now
