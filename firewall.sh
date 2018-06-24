#! /bin/bash
#
# firewall#	Written by Sebastian Baechle <s_baechl@informatik.uni-kl.de>.
#		Based on the optimized firewall script by Robert L. Ziegler
#
# Version:	@(#)firewall 1.0	(Okt 2003)
#

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
NAME="Netfilter Firewall"
DESC="Personal Netfilter Firewall"

set -e

case "$1" in
  start)
	modprobe ip_conntrack_ftp

echo -n "Initialize Personal Netfilter Firewall ."

#------------------------------> OPTIONS <------------------------------#
CONNECTION_TRACKING="1"

# AUTH-Service
ACCEPT_INT_AUTH="0"
ACCEPT_LAN_AUTH="0"

# DNS-Service
ACCEPT_INT_DNS_LSERVER="0"
ACCEPT_LAN_DNS_LSERVER="0"

ACCEPT_INT_DNS_LCLIENT="1"
ACCEPT_LAN_DNS_LCLIENT="0"

# FTP-Service
ACCEPT_INT_FTP_LSERVER="1"
ACCEPT_LAN_FTP_LSERVER="1"

ACCEPT_INT_FTP_LCLIENT="1"
ACCEPT_LAN_FTP_LCLIENT="1"

# SAMBA-Service
# ACCEPT_LAN_SAMBA muss fuer LCLIENT und LSERVER aktiviert sein
ACCEPT_LAN_SAMBA="1"
ACCEPT_LAN_SAMBA_LCLIENT="1"
ACCEPT_LAN_SAMBA_LSERVER="1"

# SSH-Service
ACCEPT_INT_SSH_LSERVER="1"
ACCEPT_LAN_SSH_LSERVER="1"

ACCEPT_INT_SSH_LCLIENT="1"
ACCEPT_LAN_SSH_LCLIENT="1"

# POP-Service
ACCEPT_INT_POP_LSERVER="0"
ACCEPT_LAN_POP_LSERVER="0"

ACCEPT_INT_POP_LCLIENT="1"
ACCEPT_LAN_POP_LCLIENT="0"

# News-Service
ACCEPT_INT_NEWS_LSERVER="0"
ACCEPT_LAN_NEWS_NEWS_LSERVER="0"

ACCEPT_INT_NEWS_LCLIENT="1"
ACCEPT_LAN_NEWS_LCLIENT="0"

# SMTP-Service
ACCEPT_INT_SMTP_LSERVER="0"
ACCEPT_LAN_SMTP_LSERVER="0"

ACCEPT_INT_SMTP_LCLIENT="1"
ACCEPT_LAN_SMTP_LCLIENT="0"

# NTP-Service
ACCEPT_INT_NTP_LSERVER="0"
ACCEPT_LAN_NTP_LSERVER="0"

ACCEPT_INT_NTP_LCLIENT="0"
ACCEPT_LAN_NTP_LCLIENT="0"

# DHCP-Service
ACCEPT_INT_DHCP_LSERVER="1"
ACCEPT_LAN_DHCP_LSERVER="1"

ACCEPT_INT_DHCP_LCLIENT="1"
ACCEPT_LAN_DHCP_LCLIENT="1"

DHCP_LAN_CLIENT="0"
DHCP_INT_CLIENT="0"

#------------------------------> /OPTIONS <------------------------------#

INTERNET="eth0"                      # Internet-connected interface
LAN="eth1"			     # LAN-connected interface
LOOPBACK_INTERFACE="lo"              # however your system names it
LAN_IPADDR="192.168.1.33"            # your LAN_IP address
INT_IPADDR="131.246.141.32"          # your INT_IP address
INT_SUBNET_BASE="131.246.0.0"        # ISP network segment base address
INT_SUBNET_BROADCAST="131.246.141.255" # network segment broadcast address
LAN_SUBNET_BASE="192.168.1.0"        # ISP network segment base address
LAN_SUBNET_BROADCAST="192.168.1.255" # network segment broadcast address
MY_ISP="131.246.0.0/16"              # ISP server & NOC address range

LAN_NAMESERVERS=""                   # addresses of lan name servers
INT_NAMESERVERS="131.246.9.116
                 131.246.137.50"     # addresses of remote internet name servers
LAN_POP_SERVERS=""                   # address of lan pop servers
INT_POP_SERVERS="217.72.192.134"     # address of internet pop servers

LAN_MAIL_SERVERS="isp.mail.server"   # address of lan mail gateways
INT_MAIL_SERVERS="131.246.137.3"     # address of internet  mail gateways

LAN_NEWS_SERVERS=""                  # address of a lan news servers
INT_NEWS_SERVERS="131.246.137.51"     # address of a internet news servers

TIME_SERVER="some.timne.server"      # address of a remote time server
DHCP_SERVER="isp.dhcp.server"        # address of your ISP dhcp server

LOOPBACK="127.0.0.0/8"               # reserved loopback address range
CLASS_A="10.0.0.0/8"                 # class A private networks
CLASS_B="172.16.0.0/12"              # class B private networks
CLASS_C="192.168.0.0/16"             # class C private networks
CLASS_D_MULTICAST="224.0.0.0/4"      # class D multicast addresses
CLASS_E_RESERVED_NET="240.0.0.0/5"   # class E reserved addresses
BROADCAST_SRC="0.0.0.0"              # broadcast source address
BROADCAST_DEST="255.255.255.255"     # broadcast destination address

PRIVPORTS="0:1023"                   # well-known, privileged port range
UNPRIVPORTS="1024:65535"             # unprivileged port range

NFS_PORT="2049"
LOCKD_PORT="4045"
SOCKS_PORT="1080"
OPENWINDOWS_PORT="2000"
XWINDOW_PORTS="6000:6063"
SQUID_PORT="3128"

# traceroute usually uses -S 32769:65535 -D 33434:33523
TRACEROUTE_SRC_PORTS="32769:65535"
TRACEROUTE_DEST_PORTS="33434:33523"


USER_CHAINS="LAN_EXT-input                 LAN_EXT-output \
             tcp-state-flags               connection-tracking  \
             source-address-check          destination-address-check  \
             LAN_local-dns-server-query	   LAN_remote-dns-server-response  \
             LAN_local-tcp-client-request  LAN_remote-tcp-server-response \
             LAN_remote-tcp-client-request LAN_local-tcp-server-response \
             LAN_remote-udp-client-request LAN_local-udp-server-response \
             LAN_local-udp-client-request  LAN_remote-udp-server-response \
             LAN_local-dhcp-client-query   LAN_rem-dhcp-server-response \
             LAN_EXT-icmp-out              LAN_EXT-icmp-in \
             LAN_EXT-log-in                LAN_EXT-log-out \
             INT_EXT-input                 INT_EXT-output \
             INT_local-dns-server-query    INT_remote-dns-server-response  \
             INT_local-tcp-client-request  INT_remote-tcp-server-response \
             INT_remote-tcp-client-request INT_local-tcp-server-response \
             INT_local-udp-client-request  INT_remote-udp-server-response \
             INT_local-dhcp-client-query   INT_rem-dhcp-server-response \
             INT_EXT-icmp-out              INT_EXT-icmp-in \
             INT_EXT-log-in                INT_EXT-log-out \
             log-tcp-state"

###############################################################

# Enable broadcast echo Protection
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Disable Source Routed Packets
for f in /proc/sys/net/ipv4/conf/*/accept_source_route; do
    echo 0 > $f
done

# Enable TCP SYN Cookie Protection
# echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Disable ICMP Redirect Acceptance
for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do
    echo 0 > $f
done

# Don¹t send Redirect Messages
for f in /proc/sys/net/ipv4/conf/*/send_redirects; do
    echo 0 > $f
done

# Drop Spoofed Packets coming in on an interface, which if replied to,
# would result in the reply going out a different interface.
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo 1 > $f
done

# Log packets with impossible addresses.
for f in /proc/sys/net/ipv4/conf/*/log_martians; do
    echo 1 > $f
done

echo -n "."

###############################################################

# Remove any existing rules from all chains
iptables --flush
iptables -t nat --flush
iptables -t mangle --flush

# Unlimited traffic on the loopback interface
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Set the default policy to drop
iptables --policy INPUT   DROP
iptables --policy OUTPUT  DROP
iptables --policy FORWARD DROP

# A bug that showed up as of the Red Hat 7.2 release results
# in the following 5 default policies breaking the firewall
# initialization:

# iptables -t nat --policy PREROUTING  DROP
# iptables -t nat --policy OUTPUT DROP
# iptables -t nat --policy POSTROUTING DROP

# iptables -t mangle --policy PREROUTING DROP
# iptables -t mangle --policy OUTPUT DROP

# Remove any pre-existing user-defined chains
iptables --delete-chain
iptables -t nat --delete-chain
iptables -t mangle --delete-chain

# Create the user-defined chains
for i in $USER_CHAINS; do
    iptables -N $i
done

echo -n "."

#------------------------------> LAN <------------------------------#

###############################################################
# DNS Caching Name Server (query to remote, primary server)

if [ "$ACCEPT_LAN_DNS_LSERVER" = "1" ]; then
    iptables -A LAN_EXT-output -p udp --sport 53 --dport 53 \
             -j LAN_local-dns-server-query

    iptables -A LAN_EXT-input -p udp --sport 53 --dport 53 \
             -j LAN_remote-dns-server-response
fi

# DNS Caching Name Server (query to remote server over TCP)

if [ "$ACCEPT_LAN_DNS_LSERVER" = "1" ]; then
    iptables -A LAN_EXT-output -p tcp \
             --sport $UNPRIVPORTS --dport 53 \
             -j LAN_local-dns-server-query

    iptables -A LAN_EXT-input -p tcp ! --syn \
             --sport 53 --dport $UNPRIVPORTS \
             -j LAN_remote-dns-server-response
fi

###############################################################
# DNS Fowarding Name Server or client requests

if [ "$ACCEPT_LAN_DNS_LCLIENT" = "1" ]; then
    iptables -A LAN_EXT-output -p udp \
             --sport $UNPRIVPORTS --dport 53 \
             -j LAN_local-dns-server-query

    iptables -A LAN_EXT-input -p udp \
             --sport 53 --dport $UNPRIVPORTS \
             -j LAN_remote-dns-server-response

    if [ "$CONNECTION_TRACKING" = "1" ]; then
        for i in $LAN_NAMESERVERS; do
        iptables -A LAN_local-dns-server-query \
                 -d $i \
                 -m state --state NEW -j ACCEPT
        done
    fi

    for i in $LAN_NAMESERVERS; do
        iptables -A LAN_local-dns-server-query \
                 -d $i -j ACCEPT
    done

    # DNS server responses to local requests

    for i in $LAN_NAMESERVERS; do
    iptables -A LAN_remote-dns-server-response \
             -s $i -j ACCEPT
    done
fi

###############################################################
# Local TCP client, remote server

iptables -A LAN_EXT-output -p tcp \
         --sport $UNPRIVPORTS \
         -j LAN_local-tcp-client-request

iptables -A LAN_EXT-input -p tcp ! --syn \
         --dport $UNPRIVPORTS \
         -j LAN_remote-tcp-server-response

###############################################################
# Local TCP client output and remote server input chains

# SSH client

if [ "$ACCEPT_LAN_SSH_LCLIENT" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A LAN_local-tcp-client-request -p tcp \
                 --dport 22 \
                 --syn -m state --state NEW \
                 -j ACCEPT
    fi

    iptables -A LAN_local-tcp-client-request -p tcp \
             --dport 22 \
             -j ACCEPT

    iptables -A LAN_remote-tcp-server-response -p tcp ! --syn \
             --sport 22  \
             -j ACCEPT
fi

#...............................................................
# Client rules for HTTP, HTTPS, AUTH, and FTP control requests

if [ "$CONNECTION_TRACKING" = "1" ]; then
    iptables -A LAN_local-tcp-client-request -p tcp \
             -m multiport --destination-port 80,443,113,21 \
             --syn -m state --state NEW \
             -j ACCEPT
fi

iptables -A LAN_local-tcp-client-request -p tcp \
         -m multiport --destination-port 80,443,113,21 \
         -j ACCEPT

iptables -A LAN_remote-tcp-server-response -p tcp \
         -m multiport --source-port 80,443,113,21  ! --syn \
         -j ACCEPT

#...............................................................
# POP3 and POPs (SSL) client

if [ "$ACCEPT_LAN_POP_LCLIENT" = "1" ]; then
    for i in $LAN_POP_SERVERS; do
        if [ "$CONNECTION_TRACKING" = "1" ]; then
            iptables -A LAN_local-tcp-client-request -p tcp \
                     -d $i --dport 110 \
                     --syn -m state --state NEW \
                     -j ACCEPT
        fi

        iptables -A LAN_local-tcp-client-request -p tcp \
                 -d $i --dport 110 \
                 -j ACCEPT

        iptables -A LAN_remote-tcp-server-response -p tcp ! --syn \
                 -s $i --sport 110  \
                 -j ACCEPT
    done
fi

if [ "$ACCEPT_LAN_POP_LCLIENT" = "1" ]; then
    for i in $LAN_POP_SERVERS; do
        if [ "$CONNECTION_TRACKING" = "1" ]; then
            iptables -A LAN_local-tcp-client-request -p tcp \
                     -d $i --dport 995 \
                     --syn -m state --state NEW \
                     -j ACCEPT
        fi

        iptables -A LAN_local-tcp-client-request -p tcp \
                 -d $i --dport 995 \
                 -j ACCEPT

        iptables -A LAN_remote-tcp-server-response -p tcp ! --syn \
                 -s $i --sport 995  \
                 -j ACCEPT
    done
fi

#...............................................................
# SMTP and SMTPs mail client

if [ "$ACCEPT_LAN_SMTP_LCLIENT" = "1" ]; then
    for i in $LAN_MAIL_SERVERS; do
        if [ "$CONNECTION_TRACKING" = "1" ]; then
            iptables -A LAN_local-tcp-client-request -p tcp \
                     -d $i --dport 25 \
                     --syn -m state --state NEW \
                     -j ACCEPT
        fi

        iptables -A LAN_local-tcp-client-request -p tcp \
                 -d $i --dport 25 \
                 -j ACCEPT

        iptables -A LAN_remote-tcp-server-response -p tcp ! --syn \
                 -s $i --sport 25  \
                -j ACCEPT
    done
fi

if [ "$ACCEPT_LAN_SMTP_LCLIENT" = "1" ]; then
    for i in $LAN_MAIL_SERVERS; do
        if [ "$CONNECTION_TRACKING" = "1" ]; then
            iptables -A LAN_local-tcp-client-request -p tcp \
                     -d $i --dport 465 \
                     --syn -m state --state NEW \
                     -j ACCEPT
        fi

        iptables -A LAN_local-tcp-client-request -p tcp \
                 -d $i --dport 465 \
                 -j ACCEPT

        iptables -A LAN_remote-tcp-server-response -p tcp ! --syn \
                 -s $i --sport 465  \
                -j ACCEPT
    done
fi

#...............................................................
# Usenet news client

if [ "$ACCEPT_LAN_NEWS_LCLIENT" = "1" ]; then
    for i in $LAN_NEWS_SERVERS; do
        if [ "$CONNECTION_TRACKING" = "1" ]; then
            iptables -A LAN_local-tcp-client-request -p tcp \
                     -d $i --dport 119 \
                     --syn -m state --state NEW \
                     -j ACCEPT
        fi

        iptables -A LAN_local-tcp-client-request -p tcp \
                 -d $i --dport 119 \
                 -j ACCEPT

        iptables -A LAN_remote-tcp-server-response -p tcp ! --syn \
                 -s $i --sport 119  \
                 -j ACCEPT
    done
fi

#...............................................................
# SAMBA client

if [ "$ACCEPT_LAN_SAMBA_LCLIENT" = "1" ]; then
        if [ "$CONNECTION_TRACKING" = "1" ]; then
            iptables -A LAN_local-tcp-client-request -p tcp \
                     --dport 137 \
                     --syn -m state --state NEW \
                     -j ACCEPT

            iptables -A LAN_local-tcp-client-request -p tcp \
                     --dport 139 \
                     --syn -m state --state NEW \
                     -j ACCEPT
        fi

        iptables -A LAN_local-tcp-client-request -p tcp \
                 --dport 139 \
                 -j ACCEPT

        iptables -A LAN_remote-tcp-server-response -p tcp ! --syn \
                 --sport 139  \
                 -j ACCEPT
fi

#...............................................................
# FTP client - passive mode data channel connection

if [ "$ACCEPT_LAN_FTP_LCLIENT" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A LAN_local-tcp-client-request -p tcp \
                 --dport $UNPRIVPORTS \
                 --syn -m state --state NEW \
                 -j ACCEPT
    fi

    iptables -A LAN_local-tcp-client-request -p tcp \
             --dport $UNPRIVPORTS -j ACCEPT

    iptables -A LAN_remote-tcp-server-response -p tcp  ! --syn \
             --sport $UNPRIVPORTS -j ACCEPT
fi

###############################################################
# Remote FTP server data channels

# Kludge for incoming FTP data channel connections
# from remote servers using port mode.
# The state modules treat this connection as RELATED
# if the ip_conntrack_ftp module is loaded.

if [ "$ACCEPT_LAN_FTP_LCLIENT" = "1" ]; then
    iptables -A LAN_EXT-input -p tcp \
             --sport 20 --dport $UNPRIVPORTS \
             -j ACCEPT

    iptables -A LAN_EXT-output -p tcp ! --syn \
             --sport $UNPRIVPORTS --dport 20 \
             -j ACCEPT
fi

###############################################################
# Local FTP server data channels

# (active) port mode

if [ "$ACCEPT_LAN_FTP_LSERVER" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A LAN_EXT-output -p tcp \
                 --sport 20 \
                 --dport $UNPRIVPORTS \
                 -m state --state NEW -j ACCEPT
    fi

    iptables -A LAN_EXT-output -p tcp \
             --sport 20 \
             --dport $UNPRIVPORTS \
             -j ACCEPT

    iptables -A LAN_EXT-input -p tcp ! --syn \
             --dport 20 \
             --sport $UNPRIVPORTS \
             -j ACCEPT
fi

# passive mode

if [ "$ACCEPT_LAN_FTP_LSERVER" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A LAN_EXT-input -p tcp \
                 --sport $UNPRIVPORTS \
                 --dport $UNPRIVPORTS \
                 -m state --state NEW -j ACCEPT
    fi

    iptables -A LAN_EXT-input -p tcp \
             --sport $UNPRIVPORTS \
             --dport $UNPRIVPORTS \
             -j ACCEPT

    iptables -A LAN_EXT-output -p tcp ! --syn \
             --dport $UNPRIVPORTS \
             --sport $UNPRIVPORTS \
             -j ACCEPT
fi

###############################################################
# Local TCP server, remote client

iptables -A LAN_EXT-input -p tcp \
         --sport $UNPRIVPORTS \
         -j LAN_remote-tcp-client-request

iptables -A LAN_EXT-output -p tcp ! --syn \
         --dport $UNPRIVPORTS \
         -j LAN_local-tcp-server-response

###############################################################
# Remote TCP client input and local server output chains

# SSH server

if [ "$ACCEPT_LAN_SSH_LSERVER" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A LAN_remote-tcp-client-request -p tcp \
                 --destination-port 22 \
                 -m state --state NEW \
                 -j ACCEPT
    fi

    iptables -A LAN_remote-tcp-client-request -p tcp \
             --destination-port 22 \
             -j ACCEPT

    iptables -A LAN_local-tcp-server-response -p tcp  ! --syn \
             --source-port 22 \
             -j ACCEPT
fi

#...............................................................
# FTP server

if [ "$ACCEPT_LAN_FTP_LSERVER" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A LAN_remote-tcp-client-request -p tcp \
                 --dport 21 \
                 -m state --state NEW \
                 -j ACCEPT
    fi

    iptables -A LAN_remote-tcp-client-request -p tcp \
             --destination-port 21 \
             -j ACCEPT

    iptables -A LAN_local-tcp-server-response -p tcp  ! --syn \
             --source-port 21 \
             -j ACCEPT
fi

#...............................................................
# AUTH identd server

if [ "$ACCEPT_LAN_AUTH_LSERVER" = "1" ]; then
    iptables -A LAN_remote-tcp-client-request -p tcp --syn \
             --destination-port 113 \
             -j REJECT --reject-with tcp-reset
else
    iptables -A LAN_remote-tcp-client-request -p tcp \
             --destination-port 113 \
             -j ACCEPT

    iptables -A LAN_local-tcp-server-response -p tcp  ! --syn \
             --source-port 113 \
             -j ACCEPT
fi

#...............................................................
# SAMBA server

if [ "$ACCEPT_LAN_SAMBA_LSERVER" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A LAN_remote-tcp-client-request -p tcp \
                 --destination-port 137 \
                 -m state --state NEW \
                 -j ACCEPT

        iptables -A LAN_remote-tcp-client-request -p tcp \
                 --destination-port 139 \
                 -m state --state NEW \
                 -j ACCEPT
    fi

    iptables -A LAN_remote-tcp-client-request -p tcp \
             --destination-port 137 \
             -j ACCEPT

    iptables -A LAN_local-tcp-server-response -p tcp  ! --syn \
             --source-port 137 \
             -j ACCEPT

    iptables -A LAN_remote-tcp-client-request -p tcp \
             --destination-port 139 \
             -j ACCEPT

    iptables -A LAN_local-tcp-server-response -p tcp  ! --syn \
             --source-port 139 \
             -j ACCEPT
fi

###############################################################
# Local UDP client, remote server

iptables -A LAN_EXT-output -p udp \
         --sport $UNPRIVPORTS \
         -j LAN_local-udp-client-request

iptables -A LAN_EXT-input -p udp \
         --dport $UNPRIVPORTS \
         -j LAN_remote-udp-server-response

###############################################################
# NTP time client

if [ "$ACCEPT_LAN_NTP_LSERVER" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A LAN_local-udp-client-request -p udp \
                 -d $TIME_SERVER --dport 123 \
                 -m state --state NEW \
                 -j ACCEPT
    fi

    iptables -A LAN_local-udp-client-request -p udp \
             -d $TIME_SERVER --dport 123 \
             -j ACCEPT

    iptables -A LAN_remote-udp-server-response -p udp \
             -s $TIME_SERVER --sport 123 \
             -j ACCEPT
fi

###############################################################
# SAMBA client

if [ "$ACCEPT_LAN_SAMBA" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A LAN_EXT-output -p udp \
                 --sport 137 --dport 137 \
                 -m state --state NEW \
                 -j ACCEPT

        iptables -A LAN_EXT-output -p udp \
                 --sport 138 --dport 138 \
                 -m state --state NEW \
                 -j ACCEPT
    fi

    iptables -A LAN_EXT-output -p udp \
             --sport 137 --dport 137 \
             -j ACCEPT

    iptables -A LAN_EXT-output -p udp \
             --sport 138 --dport 138 \
             -j ACCEPT

    iptables -A LAN_EXT-input -p udp \
             --sport 137 --dport 137 \
             -j ACCEPT

    iptables -A LAN_EXT-input -p udp \
             --sport 138 --dport 138 \
             -j ACCEPT
fi

echo -n "."

###############################################################
# ICMP

iptables -A LAN_EXT-input -p icmp -j LAN_EXT-icmp-in

iptables -A LAN_EXT-output -p icmp -j LAN_EXT-icmp-out

###############################################################
# ICMP traffic

# Log and drop initial ICMP fragments
iptables -A LAN_EXT-icmp-in --fragment -j LOG \
         --log-prefix "LAN-> Fragmented in ICMP: "

iptables -A LAN_EXT-icmp-in --fragment -j DROP

iptables -A LAN_EXT-icmp-out --fragment -j LOG \
         --log-prefix "LAN->Fragmented out ICMP: "

iptables -A LAN_EXT-icmp-out --fragment -j DROP

# Outgoing ping

if [ "$CONNECTION_TRACKING" = "1" ]; then
    iptables -A LAN_EXT-icmp-out -p icmp \
             --icmp-type echo-request \
             -m state --state NEW \
             -j ACCEPT
fi

iptables -A LAN_EXT-icmp-out -p icmp \
         --icmp-type echo-request -j ACCEPT

iptables -A LAN_EXT-icmp-in -p icmp \
         --icmp-type echo-reply -j ACCEPT

# Incoming ping

if [ "$CONNECTION_TRACKING" = "1" ]; then
    iptables -A LAN_EXT-icmp-in -p icmp \
             --icmp-type echo-request \
             -m state --state NEW \
             -j ACCEPT
fi

iptables -A LAN_EXT-icmp-in -p icmp \
         --icmp-type echo-request \
         -j ACCEPT

iptables -A LAN_EXT-icmp-out -p icmp \
         --icmp-type echo-reply \
         -j ACCEPT

# Destination Unreachable Type 3 
iptables -A LAN_EXT-icmp-out -p icmp \
         --icmp-type fragmentation-needed -j ACCEPT

iptables -A LAN_EXT-icmp-in -p icmp \
         --icmp-type destination-unreachable -j ACCEPT

# Parameter Problem
iptables -A LAN_EXT-icmp-out -p icmp \
         --icmp-type parameter-problem -j ACCEPT

iptables -A LAN_EXT-icmp-in -p icmp \
         --icmp-type parameter-problem -j ACCEPT

# Time Exceeded
iptables -A LAN_EXT-icmp-in -p icmp \
         --icmp-type time-exceeded -j ACCEPT

# Source Quench
iptables -A LAN_EXT-icmp-out -p icmp \
         --icmp-type source-quench -j ACCEPT

iptables -A LAN_EXT-icmp-in -p icmp \
         --icmp-type source-quench -j ACCEPT

echo -n "."

#------------------------------> /LAN <------------------------------#

#------------------------------> INTERNET <------------------------------#

###############################################################
# DNS Caching Name Server (query to remote, primary server)

if [ "$ACCEPT_INT_DNS_LSERVER" = "1" ]; then
    iptables -A INT_EXT-output -p udp --sport 53 --dport 53 \
             -j INT_local-dns-server-query

    iptables -A INT_EXT-input -p udp --sport 53 --dport 53 \
             -j INT_remote-dns-server-response
fi

# DNS Caching Name Server (query to remote server over TCP)

if [ "$ACCEPT_INT_DNS_LSERVER" = "1" ]; then
    iptables -A INT_EXT-output -p tcp \
             --sport $UNPRIVPORTS --dport 53 \
             -j INT_local-dns-server-query

    iptables -A INT_EXT-input -p tcp ! --syn \
             --sport 53 --dport $UNPRIVPORTS \
             -j INT_remote-dns-server-response
fi

###############################################################
# DNS Fowarding Name Server or client requests

if [ "$ACCEPT_INT_DNS_LCLIENT" = "1" ]; then
    iptables -A INT_EXT-output -p udp \
             --sport $UNPRIVPORTS --dport 53 \
             -j INT_local-dns-server-query

    iptables -A INT_EXT-input -p udp \
             --sport 53 --dport $UNPRIVPORTS \
             -j INT_remote-dns-server-response

    if [ "$CONNECTION_TRACKING" = "1" ]; then
        for i in $INT_NAMESERVERS; do
            iptables -A INT_local-dns-server-query \
                     -d $i \
                     -m state --state NEW -j ACCEPT
        done
    fi

    for i in $INT_NAMESERVERS; do
        iptables -A INT_local-dns-server-query \
                 -d $i -j ACCEPT
    done

    # DNS server responses to local requests

    for i in $INT_NAMESERVERS; do
        iptables -A INT_remote-dns-server-response \
                 -s $i -j ACCEPT
    done
fi

################################################################
# Local TCP client, remote server

iptables -A INT_EXT-output -p tcp \
         --sport $UNPRIVPORTS \
         -j INT_local-tcp-client-request

iptables -A INT_EXT-input -p tcp ! --syn \
         --dport $UNPRIVPORTS \
         -j INT_remote-tcp-server-response

###############################################################
# Local TCP client output and remote server input chains

# SSH client

if [ "$ACCEPT_INT_SSH_LCLIENT" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A INT_local-tcp-client-request -p tcp \
                 --dport 22 \
                 --syn -m state --state NEW \
                 -j ACCEPT
    fi

    iptables -A INT_local-tcp-client-request -p tcp \
             --dport 22 \
             -j ACCEPT

    iptables -A INT_remote-tcp-server-response -p tcp ! --syn \
             --sport 22  \
             -j ACCEPT
fi

#...............................................................
# Client rules for HTTP, HTTPS, AUTH, and FTP control requests

if [ "$CONNECTION_TRACKING" = "1" ]; then
    iptables -A INT_local-tcp-client-request -p tcp \
             -m multiport --destination-port 80,443,113,21 \
             --syn -m state --state NEW \
             -j ACCEPT
fi

iptables -A INT_local-tcp-client-request -p tcp \
         -m multiport --destination-port 80,443,113,21 \
         -j ACCEPT

iptables -A INT_remote-tcp-server-response -p tcp \
         -m multiport --source-port 80,443,113,21  ! --syn \
         -j ACCEPT

#...............................................................
# POP3 and POPs (SSL) client

if [ "$ACCEPT_INT_POP_LCLIENT" = "1" ]; then
    for i in $INT_POP_SERVERS; do
        if [ "$CONNECTION_TRACKING" = "1" ]; then
            iptables -A INT_local-tcp-client-request -p tcp \
                     -d $i --dport 110 \
                     --syn -m state --state NEW \
                     -j ACCEPT
        fi

        iptables -A INT_local-tcp-client-request -p tcp \
                 -d $i --dport 110 \
                 -j ACCEPT

        iptables -A INT_remote-tcp-server-response -p tcp ! --syn \
                 -s $i --sport 110  \
                 -j ACCEPT
    done
fi

if [ "$ACCEPT_INT_POP_LCLIENT" = "1" ]; then
    for i in $INT_POP_SERVERS; do
        if [ "$CONNECTION_TRACKING" = "1" ]; then
            iptables -A INT_local-tcp-client-request -p tcp \
                     -d $i --dport 995 \
                     --syn -m state --state NEW \
                     -j ACCEPT
        fi

        iptables -A INT_local-tcp-client-request -p tcp \
                 -d $i --dport 995 \
                 -j ACCEPT

        iptables -A INT_remote-tcp-server-response -p tcp ! --syn \
                 -s $i --sport 995  \
                 -j ACCEPT
    done
fi

#...............................................................
# SMTP and SMTPs mail client

if [ "$ACCEPT_INT_SMTP_LCLIENT" = "1" ]; then
    for i in $INT_MAIL_SERVERS; do
        if [ "$CONNECTION_TRACKING" = "1" ]; then
            iptables -A INT_local-tcp-client-request -p tcp \
                     -d $i --dport 25 \
                     --syn -m state --state NEW \
                     -j ACCEPT
        fi

        iptables -A INT_local-tcp-client-request -p tcp \
                 -d $i --dport 25 \
                 -j ACCEPT

        iptables -A INT_remote-tcp-server-response -p tcp ! --syn \
                 -s $i --sport 25  \
                 -j ACCEPT
    done
fi

if [ "$ACCEPT_INT_SMTP_LCLIENT" = "1" ]; then
    for i in $INT_MAIL_SERVERS; do
        if [ "$CONNECTION_TRACKING" = "1" ]; then
            iptables -A INT_local-tcp-client-request -p tcp \
                     -d $i --dport 465 \
                     --syn -m state --state NEW \
                     -j ACCEPT
        fi

        iptables -A INT_local-tcp-client-request -p tcp \
                 -d $i --dport 465 \
                 -j ACCEPT

        iptables -A INT_remote-tcp-server-response -p tcp ! --syn \
                 -s $i --sport 465  \
                 -j ACCEPT
    done
fi

#...............................................................
# Usenet news client

if [ "$ACCEPT_INT_NEWS_LCLIENT" = "1" ]; then
    for i in $INT_NEWS_SERVERS; do
        if [ "$CONNECTION_TRACKING" = "1" ]; then
            iptables -A INT_local-tcp-client-request -p tcp \
                     -d $i --dport 119 \
                     --syn -m state --state NEW \
                     -j ACCEPT
        fi

        iptables -A INT_local-tcp-client-request -p tcp \
                 -d $i --dport 119 \
                 -j ACCEPT

        iptables -A INT_remote-tcp-server-response -p tcp ! --syn \
                 -s $i --sport 119  \
                 -j ACCEPT
    done
fi

#...............................................................
# FTP client - passive mode data channel connection


if [ "$ACCEPT_INT_FTP_LCLIENT" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A INT_local-tcp-client-request -p tcp \
                 --dport $UNPRIVPORTS \
                 --syn -m state --state NEW \
                 -j ACCEPT
    fi

    iptables -A INT_local-tcp-client-request -p tcp \
             --dport $UNPRIVPORTS -j ACCEPT

    iptables -A INT_remote-tcp-server-response -p tcp  ! --syn \
             --sport $UNPRIVPORTS -j ACCEPT
fi

###############################################################
# Remote FTP server data channels

# Kludge for incoming FTP data channel connections
# from remote servers using port mode.
# The state modules treat this connection as RELATED
# if the ip_conntrack_ftp module is loaded.

if [ "$ACCEPT_INT_FTP_LCLIENT" = "1" ]; then
    iptables -A INT_EXT-input -p tcp \
             --sport 20 --dport $UNPRIVPORTS \
             -j ACCEPT

    iptables -A INT_EXT-output -p tcp ! --syn \
             --sport $UNPRIVPORTS --dport 20 \
             -j ACCEPT
fi

###############################################################
# Local FTP server data channels

# (active) port mode

if [ "$ACCEPT_INT_FTP_LSERVER" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A INT_EXT-output -p tcp \
                 --sport 20 \
                 --dport $UNPRIVPORTS \
                 -m state --state NEW -j ACCEPT
    fi

    iptables -A INT_EXT-output -p tcp \
             --sport 20 \
             --dport $UNPRIVPORTS \
             -j ACCEPT

    iptables -A INT_EXT-input -p tcp ! --syn \
             --dport 20 \
             --sport $UNPRIVPORTS \
             -j ACCEPT
fi

# passive mode

if [ "$ACCEPT_INT_FTP_LSERVER" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A INT_EXT-input -p tcp \
                 --sport $UNPRIVPORTS \
                 --dport $UNPRIVPORTS \
                 -m state --state NEW -j ACCEPT
    fi

    iptables -A INT_EXT-input -p tcp \
             --sport $UNPRIVPORTS \
             --dport $UNPRIVPORTS \
             -j ACCEPT

    iptables -A INT_EXT-output -p tcp ! --syn \
             --dport $UNPRIVPORTS \
             --sport $UNPRIVPORTS \
             -j ACCEPT
fi

###############################################################
# Local TCP server, remote client

iptables -A INT_EXT-input -p tcp \
         --sport $UNPRIVPORTS \
         -j INT_remote-tcp-client-request

iptables -A INT_EXT-output -p tcp ! --syn \
         --dport $UNPRIVPORTS \
         -j INT_local-tcp-server-response

###############################################################
# Remote TCP client input and local server output chains

# SSH server

if [ "$ACCEPT_INT_SSH_LSERVER" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A INT_remote-tcp-client-request -p tcp \
                 --destination-port 22 \
                 -m state --state NEW \
                 -j ACCEPT
    fi

    iptables -A INT_remote-tcp-client-request -p tcp \
             --destination-port 22 \
             -j ACCEPT

    iptables -A INT_local-tcp-server-response -p tcp  ! --syn \
             --source-port 22 \
             -j ACCEPT
fi

#..............................................................
# FTP server

if [ "$ACCEPT_INT_FTP_LSERVER" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A INT_remote-tcp-client-request -p tcp \
                 --dport 21 \
                 -m state --state NEW \
                 -j ACCEPT
    fi

    iptables -A INT_remote-tcp-client-request -p tcp \
             --destination-port 21 \
             -j ACCEPT

    iptables -A INT_local-tcp-server-response -p tcp  ! --syn \
             --source-port 21 \
             -j ACCEPT
fi

#...............................................................
# AUTH identd server

if [ "$ACCEPT_INT_AUTH_LSERVER" = "1" ]; then
    iptables -A INT_remote-tcp-client-request -p tcp --syn \
             --destination-port 113 \
             -j REJECT --reject-with tcp-reset
else
    iptables -A INT_remote-tcp-client-request -p tcp \
             --destination-port 113 \
             -j ACCEPT

    iptables -A INT_local-tcp-server-response -p tcp  ! --syn \
             --source-port 113 \
             -j ACCEPT
fi

###############################################################
# Local UDP client, remote server

iptables -A INT_EXT-output -p udp \
         --sport $UNPRIVPORTS \
         -j INT_local-udp-client-request

iptables -A INT_EXT-input -p udp \
         --dport $UNPRIVPORTS \
         -j INT_remote-udp-server-response

###############################################################
# NTP time client

if [ "$ACCEPT_INT_NTP_LSERVER" = "1" ]; then
    if [ "$CONNECTION_TRACKING" = "1" ]; then
        iptables -A INT_local-udp-client-request -p udp \
                 -d $TIME_SERVER --dport 123 \
                 -m state --state NEW \
                 -j ACCEPT
    fi

    iptables -A INT_local-udp-client-request -p udp \
             -d $TIME_SERVER --dport 123 \
             -j ACCEPT

    iptables -A INT_remote-udp-server-response -p udp \
             -s $TIME_SERVER --sport 123 \
             -j ACCEPT
fi

echo -n "."

###############################################################
# ICMP

iptables -A INT_EXT-input -p icmp -j INT_EXT-icmp-in

iptables -A INT_EXT-output -p icmp -j INT_EXT-icmp-out

###############################################################
# ICMP traffic

# Log and drop initial ICMP fragments
iptables -A INT_EXT-icmp-in --fragment -j LOG \
         --log-prefix "INT-> Fragmented in ICMP: "

iptables -A INT_EXT-icmp-in --fragment -j DROP

iptables -A INT_EXT-icmp-out --fragment -j LOG \
         --log-prefix "INT-> Fragmented out ICMP: "

iptables -A INT_EXT-icmp-out --fragment -j DROP

# Outgoing ping

if [ "$CONNECTION_TRACKING" = "1" ]; then
    iptables -A INT_EXT-icmp-out -p icmp \
             --icmp-type echo-request \
             -m state --state NEW \
             -j ACCEPT
fi

iptables -A INT_EXT-icmp-out -p icmp \
         --icmp-type echo-request -j ACCEPT

iptables -A INT_EXT-icmp-in -p icmp \
         --icmp-type echo-reply -j ACCEPT

# Incoming ping

if [ "$CONNECTION_TRACKING" = "1" ]; then
    iptables -A INT_EXT-icmp-in -p icmp \
             -s $MY_ISP  \
             --icmp-type echo-request \
             -m state --state NEW \
             -j ACCEPT
fi

iptables -A INT_EXT-icmp-in -p icmp \
         --icmp-type echo-request \
         -s $MY_ISP -j ACCEPT

iptables -A INT_EXT-icmp-out -p icmp \
         --icmp-type echo-reply \
         -d $MY_ISP -j ACCEPT

# Destination Unreachable Type 3
iptables -A INT_EXT-icmp-out -p icmp \
         --icmp-type fragmentation-needed -j ACCEPT

iptables -A INT_EXT-icmp-in -p icmp \
         --icmp-type destination-unreachable -j ACCEPT

# Parameter Problem
iptables -A INT_EXT-icmp-out -p icmp \
         --icmp-type parameter-problem -j ACCEPT

iptables -A INT_EXT-icmp-in -p icmp \
         --icmp-type parameter-problem -j ACCEPT

# Time Exceeded
iptables -A INT_EXT-icmp-in -p icmp \
         --icmp-type time-exceeded -j ACCEPT

# Source Quench
iptables -A INT_EXT-icmp-out -p icmp \
         --icmp-type source-quench -j ACCEPT

iptables -A INT_EXT-icmp-in -p icmp \
         --icmp-type source-quench -j ACCEPT

echo -n "."

#------------------------------> /INTERNET <------------------------------#

###############################################################
# TCP State Flags

# All of the bits are cleared
iptables -A tcp-state-flags -p tcp --tcp-flags ALL NONE -j log-tcp-state

# SYN and FIN are both set
iptables -A tcp-state-flags -p tcp --tcp-flags SYN,FIN SYN,FIN -j log-tcp-state

# SYN and RST are both set
iptables -A tcp-state-flags -p tcp --tcp-flags SYN,RST SYN,RST -j log-tcp-state

# FIN and RST are both set
iptables -A tcp-state-flags -p tcp --tcp-flags FIN,RST FIN,RST -j log-tcp-state

# FIN is the only bit set, without the expected accompanying ACK
iptables -A tcp-state-flags -p tcp --tcp-flags ACK,FIN FIN -j log-tcp-state

# PSH is the only bit set, without the expected accompanying ACK
iptables -A tcp-state-flags -p tcp --tcp-flags ACK,PSH PSH -j log-tcp-state

# URG is the only bit set, without the expected accompanying ACK
iptables -A tcp-state-flags -p tcp --tcp-flags ACK,URG URG -j log-tcp-state

###############################################################
# Log and drop TCP packets with bad state combinations

iptables -A log-tcp-state -p tcp -j LOG \
         --log-prefix "Illegal TCP state: " \
         --log-ip-options --log-tcp-options

iptables -A log-tcp-state -j DROP

###############################################################
# By-pass rule checking for ESTABLISHED exchanges

if [ "$CONNECTION_TRACKING" = "1" ]; then
    iptables -A connection-tracking -m state \
             --state ESTABLISHED,RELATED \
             -j ACCEPT

    # By-pass the firewall filters for established exchanges
    iptables -A connection-tracking -m state --state INVALID \
             -j LOG --log-prefix "INVALID packet: "
    iptables -A connection-tracking -m state --state INVALID -j DROP
fi

###############################################################
# DHCP traffic

# Some broadcast packets are explicitly ignored by the firewall.
# Others are dopped by the default policy.
# DHCP tests must precede broadcast-related rules, as DHCP relies
# on broadcast traffic initially.

if [ "$DHCP_CLIENT" = "1" ]; then
    DHCP_SERVER="my.dhcp.server"

    # Initialization or rebinding: No lease or Lease time expired.

    iptables -A LAN_local-dhcp-client-query \
             -s $BROADCAST_SRC \
             -d $BROADCAST_DEST -j ACCEPT

    # Incoming DHCPOFFER from available DHCP servers

    iptables -A LAN_rem-dhcp-server-response \
             -s $BROADCAST_SRC \
             -d $BROADCAST_DEST -j ACCEPT

    # Fall back to initialization
    # The client knows its server, but has either lost its lease,
    # or else needs to reconfirm the IP address after rebooting.

    iptables -A LAN_local-dhcp-client-query \
                 -s $BROADCAST_SRC \
                 -d $DHCP_SERVER -j ACCEPT

    iptables -A LAN_rem-dhcp-server-response \
             -s $DHCP_SERVER \
             -d $BROADCAST_DEST -j ACCEPT

    # As a result of the above, we're supposed to change our IP
    # address with this message, which is addressed to our new
    # address before the dhcp client has received the update.
    # Depending on the server implementation, the destination address
    # can be the new IP address, the subnet address, or the limited
    # broadcast address.

    # If the network subnet address is used as the destination,
    # the next rule must allow incoming packets destined to the
    # subnet address, and the rule must precede any general rules
    # that block such incoming broadcast packets.

    iptables -A LAN_rem-dhcp-server-response \
             -s $DHCP_SERVER -j ACCEPT

    # Lease renewal

    iptables -A LAN_local-dhcp-client-query \
             -s $IPADDR \
             -d $DHCP_SERVER -j ACCEPT
fi

###############################################################
# Masquerading

    iptables -t nat -A POSTROUTING -o $INTERNET -j MASQUERADE

    iptables -A FORWARD -o $INTERNET -m state \
                --state NEW,ESTABLISHED,RELATED -j ACCEPT

    iptables -A FORWARD -o $LAN -m state \
               --state NEW,ESTABLISHED,RELATED -j ACCEPT

###############################################################
# Source Address Spoof Checks

# Drop packets pretending to be originating from the receiving interface
iptables -A source-address-check -i $LAN -s $LAN_IPADDR -j DROP
iptables -A source-address-check -i $INTERNET -s $INT_IPADDR -j DROP

# Refuse packets claiming to be from private networks

iptables -A source-address-check -s $CLASS_A -j DROP
iptables -A source-address-check -s $CLASS_B -j DROP
iptables -A source-address-check -i $INTERNET -s $CLASS_C -j DROP
iptables -A source-address-check -s $CLASS_D_MULTICAST -j DROP
iptables -A source-address-check -s $CLASS_E_RESERVED_NET -j DROP
iptables -A source-address-check -s $LOOPBACK  -j DROP

iptables -A source-address-check -d $BROADCAST_DEST -j DROP

iptables -A source-address-check -s 0.0.0.0/8 -j DROP
iptables -A source-address-check -s 169.254.0.0/16 -j DROP
iptables -A source-address-check -i $INTERNET -s 192.0.2.0/24 -j DROP

###############################################################


# Bad Destination Address and Port Checks

# Block directed broadcasts from the Internet

iptables -A destination-address-check -i $LAN -d $LAN_SUBNET_BASE -j ACCEPT
iptables -A destination-address-check -i $LAN -d $LAN_SUBNET_BROADCAST -j ACCEPT

iptables -A destination-address-check -i $INTERNET -d $INT_SUBNET_BASE -j DROP
iptables -A destination-address-check -i $INTERNET -d $INT_SUBNET_BROADCAST -j DROP
iptables -A destination-address-check -p ! udp -d $CLASS_D_MULTICAST -j DROP

# Avoid ports subject to protocol and system administration problems

# TCP unprivileged ports
# Deny connection requests to NFS, SOCKS and X Window ports
iptables -A destination-address-check -p tcp -m multiport \
         --destination-port $NFS_PORT,$OPENWINDOWS_PORT,$SOCKS_PORT,$SQUID_PORT \
         --syn -j DROP

iptables -A destination-address-check -p tcp --syn \
         --destination-port $XWINDOW_PORTS -j DROP

# UDP unprivileged ports
# Deny connection requests to NFS and lockd ports
iptables -A destination-address-check -p udp -m multiport \
         --destination-port $NFS_PORT,$LOCKD_PORT -j DROP

echo -n "."

###############################################################
# LAN: Logging Rules Prior to Dropping by the Default Policy

# ICMP rules

iptables -A LAN_EXT-log-in -p icmp \
         --icmp-type ! echo-request -m limit -j LOG

# TCP rules

iptables -A LAN_EXT-log-in -p tcp \
         --dport 0:19 -j LOG

# skip ftp, telnet, ssh
iptables -A LAN_EXT-log-in -p tcp \
         --dport 24 -j LOG

# skip smtp
iptables -A LAN_EXT-log-in -p tcp \
         --dport 26:78 -j LOG

# skip finger, www
iptables -A LAN_EXT-log-in -p tcp \
         --dport 81:109 -j LOG

# skip pop-3, sunrpc
iptables -A LAN_EXT-log-in -p tcp \
         --dport 112:136 -j LOG

# skip NetBIOS
iptables -A LAN_EXT-log-in -p tcp \
         --dport 140:142 -j LOG

# skip imap
iptables -A LAN_EXT-log-in -p tcp \
         --dport 144:442 -j LOG

# skip secure_web/SSL
iptables -A LAN_EXT-log-in -p tcp \
         --dport 444:65535 -j LOG

#UDP rules

iptables -A LAN_EXT-log-in -p udp \
         --dport 0:110 -j LOG

# skip sunrpc
iptables -A LAN_EXT-log-in -p udp \
         --dport 112:160 -j LOG

# skip snmp
iptables -A LAN_EXT-log-in -p udp \
         --dport 163:634 -j LOG

# skip NFS mountd
iptables -A LAN_EXT-log-in -p udp \
         --dport 636:5631 -j LOG

# skip pcAnywhere
iptables -A LAN_EXT-log-in -p udp \
         --dport 5633:31336 -j LOG

# skip traceroute¹s default ports
iptables -A LAN_EXT-log-in -p udp \
         --sport $TRACEROUTE_SRC_PORTS \
         --dport $TRACEROUTE_DEST_PORTS -j LOG

# skip the rest
iptables -A LAN_EXT-log-in -p udp \
         --dport 33434:65535 -j LOG

# Outgoing Packets

# Don't log rejected outgoing ICMP destination-unreachable packets
iptables -A LAN_EXT-log-out -p icmp \
         --icmp-type destination-unreachable -j DROP

iptables -A LAN_EXT-log-out -j LOG 

###############################################################
# INTERNET: Logging Rules Prior to Dropping by the Default Policy

# ICMP rules

iptables -A INT_EXT-log-in -p icmp \
        --icmp-type ! echo-request -m limit -j LOG

# TCP rules

iptables -A INT_EXT-log-in -p tcp \
         --dport 0:19 -j LOG

# skip ftp, telnet, ssh
iptables -A INT_EXT-log-in -p tcp \
         --dport 24 -j LOG

# skip smtp
iptables -A INT_EXT-log-in -p tcp \
         --dport 26:78 -j LOG

# skip finger, www
iptables -A INT_EXT-log-in -p tcp \
         --dport 81:109 -j LOG

# skip pop-3, sunrpc
iptables -A INT_EXT-log-in -p tcp \
         --dport 112:136 -j LOG

# skip NetBIOS
iptables -A INT_EXT-log-in -p tcp \
         --dport 140:142 -j LOG

# skip imap
iptables -A INT_EXT-log-in -p tcp \
         --dport 144:442 -j LOG

# skip secure_web/SSL
iptables -A INT_EXT-log-in -p tcp \
         --dport 444:65535 -j LOG

#UDP rules

iptables -A INT_EXT-log-in -p udp \
         --dport 0:110 -j LOG

# skip sunrpc
iptables -A INT_EXT-log-in -p udp \
         --dport 112:160 -j LOG

# skip snmp
iptables -A INT_EXT-log-in -p udp \
         --dport 163:634 -j LOG

# skip NFS mountd
iptables -A INT_EXT-log-in -p udp \
         --dport 636:5631 -j LOG

# skip pcAnywhere
iptables -A INT_EXT-log-in -p udp \
         --dport 5633:31336 -j LOG

# skip traceroute¹s default ports
iptables -A INT_EXT-log-in -p udp \
         --sport $TRACEROUTE_SRC_PORTS \
         --dport $TRACEROUTE_DEST_PORTS -j LOG

# skip the rest
iptables -A INT_EXT-log-in -p udp \
         --dport 33434:65535 -j LOG

# Outgoing Packets

# Don't log rejected outgoing ICMP destination-unreachable packets
iptables -A INT_EXT-log-out -p icmp \
         --icmp-type destination-unreachable -j DROP

iptables -A INT_EXT-log-out -j LOG

echo -n ". "

###############################################################
# Install the User-defined Chains on the built-in
# INPUT and OUTPUT chains

# If TCP: Check for common stealth scan TCP state patterns
iptables -A INPUT  -p tcp -j tcp-state-flags
iptables -A OUTPUT -p tcp -j tcp-state-flags

if [ "$CONNECTION_TRACKING" = "1" ]; then
    # By-pass the firewall filters for established exchanges
    iptables -A INPUT  -j connection-tracking
    iptables -A OUTPUT -j connection-tracking
fi

if [ "$DHCP_LAN_CLIENT" = "1" ]; then
    iptables -A INPUT  -i $LAN -p udp \
             --sport 67 --dport 68 -j LAN_rem-dhcp-server-response
    iptables -A OUTPUT -o $LAN -p udp \
             --sport 68 --dport 67 -j LAN_local-dhcp-client-query
fi

if [ "$DHCP_INT_CLIENT" = "1" ]; then
    iptables -A INPUT  -i $INTERNET -p udp \
             --sport 67 --dport 68 -j INT_rem-dhcp-server-response
    iptables -A OUTPUT -o $INTERNET -p udp \
             --sport 68 --dport 67 -j INT_local-dhcp-client-query
fi

# Test for illegal source and destination addresses in incoming packets
iptables -A INPUT  -p ! tcp -j source-address-check
iptables -A INPUT  -p tcp --syn -j source-address-check
iptables -A INPUT  -j destination-address-check

# Test for illegal destination addresses in outgoing packets
iptables -A OUTPUT -j destination-address-check

# Begin standard firewall tests for packets addressed to this host
iptables -A INPUT -i $LAN -d $LAN_IPADDR -j LAN_EXT-input
iptables -A INPUT -i $INTERNET -d $INT_IPADDR -j INT_EXT-input

# Multicast traffic
iptables -A INPUT  -i $LAN -p udp -d $CLASS_D_MULTICAST -j ACCEPT
iptables -A OUTPUT -o $LAN -p udp -s $LAN_IPADDR -d $CLASS_D_MULTICAST -j ACCEPT

iptables -A INPUT  -i $INTERNET -p udp -d $CLASS_D_MULTICAST -j DROP
iptables -A OUTPUT -o $INTERNET -p udp -s $INT_IPADDR -d $CLASS_D_MULTICAST -j DROP

# Begin standard firewall tests for packets sent from this host
# Source address spoofing by this host is  not allowed due to the
# test on source address in this rule.
iptables -A OUTPUT -o $LAN -s $LAN_IPADDR -j LAN_EXT-output
iptables -A OUTPUT -o $INTERNET -s $INT_IPADDR -j INT_EXT-output

# Log anything of interest that fell through,
# before the default policy drops the packet.
iptables -A INPUT  -i $INTERNET -s $INT_IPADDR -j INT_EXT-log-in
iptables -A OUTPUT -o $INTERNET -s $INT_IPADDR -j INT_EXT-log-out

iptables -A INPUT  -i $LAN -s $LAN_IPADDR -j LAN_EXT-log-in
iptables -A OUTPUT -o $LAN -s $LAN_IPADDR -j LAN_EXT-log-out

echo "done"

;;

  stop)
	echo "Stopping $DESC"
	# Enable broadcast echo Protection
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Disable Source Routed Packets
for f in /proc/sys/net/ipv4/conf/*/accept_source_route; do
    echo 0 > $f
done

# Enable TCP SYN Cookie Protection
# echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Disable ICMP Redirect Acceptance
for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do
    echo 0 > $f
done

# Don¹t send Redirect Messages
for f in /proc/sys/net/ipv4/conf/*/send_redirects; do
    echo 0 > $f
done

# Drop Spoofed Packets coming in on an interface, which if replied to,
# would result in the reply going out a different interface.
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo 1 > $f
done

# Log packets with impossible addresses.
for f in /proc/sys/net/ipv4/conf/*/log_martians; do
    echo 1 > $f
done

###############################################################

# Remove any existing rules from all chains
iptables --flush
iptables -t nat --flush
iptables -t mangle --flush

# Unlimited traffic on the loopback interface
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Set the default policy to drop
iptables --policy INPUT   ACCEPT
iptables --policy OUTPUT  ACCEPT
iptables --policy FORWARD ACCEPT

# A bug that showed up as of the Red Hat 7.2 release results
# in the following 5 default policies breaking the firewall
# initialization:

# iptables -t nat --policy PREROUTING  DROP
# iptables -t nat --policy OUTPUT DROP
# iptables -t nat --policy POSTROUTING DROP

# iptables -t mangle --policy PREROUTING DROP
# iptables -t mangle --policy OUTPUT DROP

# Remove any pre-existing user-defined chains
iptables --delete-chain
iptables -t nat --delete-chain
iptables -t mangle --delete-chain

;;

  *)
	N=/etc/init.d/$NAME
	# echo "Usage: $N {start|stop|restart|reload|force-reload}" >&2
	echo "Usage: $N {start|stop}" >&2
	exit 1
	;;
esac

exit 0
