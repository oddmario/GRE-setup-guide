# Setup a GRE tunnel between two Linux servers

TL;DR network engineering is hard 🫠

## Server A
It is the "GRE VPS" which we are going to use the IP address of instead of the IP address of Server B.

One recommended provider for Server A is BuyVM.net [especially with their DDoS protected IPs]

## Server B
It is the "backend server" or the destination server. i.e. the server which we are trying to hide/protect the IP address of.

## This guide covers
- Setting up a GRE tunnel to link between two Linux servers (server A and server B)
- Setting up the proper routing to make server A forward all the traffic to & from server B through the tunnel.

If you would like to use WireGuard (or OpenVPN) instead of a GRE tunnel to link between the two servers, you can absolutely give that a go!

Generally, we just need a way to link between the two servers (either GRE, WireGuard or even OpenVPN). Then the rest of the commands to setup the routing through iproute2 and iptables should be similar.

## Requirements
- Server A needs to have at least one primary public IP address that we are going to use as the peer address for our GRE tunnel(s).
- And similary, Server B needs to have at least one primary public IP address so we can use it inside the tunnel.
- Make sure the following packages are installed on the systems of both server A and server B:
     - iproute2 (the `ip` command)
     - iproute-tc (the `tc` command)

-----

## Tunnel setup scripts

`makeGRE.sh` on Server A:
```
#!/bin/bash

# This script is placed on the GRE VPS

#
# Variables
#

GRE_VPS_MAIN_IP="[the main public ip address of the gre vps here]" # NOTE: this is recommended to be the main public IP of the GRE VPS. even if you are trying to use an additional IP that belongs to the GRE VPS, it's nicer to put the main IP address here.
# GRE_VPS_IP below doesn't have to be the main IP address of the GRE VPS. you can put an additional/secondary public IP linked to the GRE VPS here if that's what you are attempting to make the GRE tunnel use to forward all the traffic to server B. However if the GRE VPS has only one public IP (which is the main IP address), you can put it here.
GRE_VPS_IP="[the gre vps public ip address that you are attempting to make its traffic get forwarded to the backend server]"
BACKEND_IP="[backend server public ip address here]"
GRE_VPS_MAIN_INTERFACE="eth0"

GRE_TUNNEL_INTERFACE_NAME="gre1"
GRE_TUNNEL_GATEWAY_IP="192.168.168.0"
GRE_TUNNEL_GREVPS_IP="192.168.168.1"
GRE_TUNNEL_BACKEND_IP="192.168.168.2"
GRE_TUNNEL_KEY="1"

# ----------------------------------

# enable the gre kernel module [if needed]
modprobe ip_gre

# stop & disable the firewall to avoid issues
systemctl stop firewalld
systemctl disable firewalld

modprobe ip_conntrack
# enable the required kernel tweaks for the purpose of tunneling
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.$GRE_VPS_MAIN_INTERFACE.proxy_arp=1
## https://serverfault.com/a/359232/554686
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0

# additional kernel tweaks
sysctl -w net.ipv4.tcp_mtu_probing=1
sysctl -w fs.file-max=2097152
sysctl -w fs.inotify.max_user_instances=2097152
sysctl -w fs.inotify.max_user_watches=2097152
sysctl -w fs.nr_open=2097152
sysctl -w fs.aio-max-nr=2097152
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sysctl -w net.core.netdev_max_backlog=99999
sysctl -w net.ipv4.ip_local_port_range="16384 65535"
sysctl -w net.nf_conntrack_max=1000000
sysctl -w net.netfilter.nf_conntrack_max=1000000
sysctl -w net.ipv4.tcp_max_tw_buckets=1440000
sysctl -w net.ipv4.tcp_congestion_control=bbr
sysctl -w net.core.default_qdisc=noqueue

sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1

# tune the networking
modprobe tcp_bbr
tc qdisc replace dev $GRE_VPS_MAIN_INTERFACE root noqueue
ip link set $GRE_VPS_MAIN_INTERFACE txqueuelen 99999

# clear all iptables rules
iptables -F

# create a new gre tunnel
# setting a `key` below is not necessary, however we do it in case there will be multiple gre tunnels with the same local and remote ips. iproute will consider this a duplicate tunnel (even with a different $GRE_TUNNEL_INTERFACE_NAME) and thus will fail to add it, unless a key is added.
ip tunnel add $GRE_TUNNEL_INTERFACE_NAME mode gre local $GRE_VPS_MAIN_IP remote $BACKEND_IP ttl 255 key $GRE_TUNNEL_KEY

# add $GRE_TUNNEL_GREVPS_IP as an IP for peer A on our newly created gre interface
ip addr add $GRE_TUNNEL_GREVPS_IP/30 dev $GRE_TUNNEL_INTERFACE_NAME

# bring the gre interface up
ip link set $GRE_TUNNEL_INTERFACE_NAME up

# ensure that iptables won't block any traffic from/to peer B
iptables -A FORWARD -i $GRE_TUNNEL_INTERFACE_NAME -j ACCEPT
iptables -A FORWARD -d $GRE_TUNNEL_BACKEND_IP -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -s $GRE_TUNNEL_BACKEND_IP -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# forward any traffic coming from the $GRE_TUNNEL_GATEWAY_IP/30 subnet to the public IP of server A. this will give server B the ability to use the network of server A through the gre tunnel
iptables -t nat -A POSTROUTING -s $GRE_TUNNEL_GATEWAY_IP/30 ! -o $GRE_TUNNEL_INTERFACE_NAME -j SNAT --to-source $GRE_VPS_IP

# forward any traffic coming to the public IP of server A to server B. be warned that upon running the below command, you won't be able to access the original server A through its public IP anymore. it will mostly connect you to server B instead
iptables -t nat -A PREROUTING -d $GRE_VPS_IP -j DNAT --to-destination $GRE_TUNNEL_BACKEND_IP

# tune the gre interface
tc qdisc replace dev $GRE_TUNNEL_INTERFACE_NAME root noqueue
ip link set $GRE_TUNNEL_INTERFACE_NAME txqueuelen 99999
```

`delGRE.sh` on Server A:
```
#!/bin/bash

# This script is placed on the GRE VPS

#
# Variables
#

# GRE_VPS_IP below doesn't have to be the main IP address of the GRE VPS. you can put an additional/secondary public IP linked to the GRE VPS here if that's what you are attempting to make the GRE tunnel use to forward all the traffic to server B. However if the GRE VPS has only one public IP (which is the main IP address), you can put it here.
GRE_VPS_IP="[the gre vps public ip address that you are attempting to make its traffic get forwarded to the backend server]"

GRE_TUNNEL_INTERFACE_NAME="gre1"
GRE_TUNNEL_GATEWAY_IP="192.168.168.0"
GRE_TUNNEL_GREVPS_IP="192.168.168.1"
GRE_TUNNEL_BACKEND_IP="192.168.168.2"

# ----------------------------------

iptables -D FORWARD -i $GRE_TUNNEL_INTERFACE_NAME -j ACCEPT
iptables -D FORWARD -d $GRE_TUNNEL_BACKEND_IP -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -D FORWARD -s $GRE_TUNNEL_BACKEND_IP -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -D POSTROUTING -s $GRE_TUNNEL_GATEWAY_IP/30 ! -o $GRE_TUNNEL_INTERFACE_NAME -j SNAT --to-source $GRE_VPS_IP
iptables -t nat -D PREROUTING -d $GRE_VPS_IP -j DNAT --to-destination $GRE_TUNNEL_BACKEND_IP
ip addr del $GRE_TUNNEL_GREVPS_IP/30 dev $GRE_TUNNEL_INTERFACE_NAME
ip link set $GRE_TUNNEL_INTERFACE_NAME down
ip tunnel del $GRE_TUNNEL_INTERFACE_NAME
```

`makeGRE.sh` on Server B:
```
#!/bin/bash

# This script is placed on the backend server

#
# Variables
#

GRE_VPS_MAIN_IP="[the main public ip address of the gre vps here]" # NOTE: this is recommended to be the main public IP of the GRE VPS. even if you are trying to use an additional IP that belongs to the GRE VPS, it's nicer to put the main IP address here.
BACKEND_IP="[backend server public ip address here]"

GRE_TUNNEL_INTERFACE_NAME="gre1"
GRE_TUNNEL_GATEWAY_IP="192.168.168.0"
GRE_TUNNEL_GREVPS_IP="192.168.168.1"
GRE_TUNNEL_BACKEND_IP="192.168.168.2"
GRE_TUNNEL_KEY="1"

GRE_TUNNEL_RTTABLES_ID="100"
GRE_TUNNEL_RTTABLES_NAME="GRETUN"

# ----------------------------------

# enable the gre kernel module [if needed]
modprobe ip_gre

# create a new gre tunnel
# setting a `key` below is not necessary, however we do it in case there will be multiple gre tunnels with the same local and remote ips. iproute will consider this a duplicate tunnel (even with a different $GRE_TUNNEL_INTERFACE_NAME) and thus will fail to add it, unless a key is added.
ip tunnel add $GRE_TUNNEL_INTERFACE_NAME mode gre local $BACKEND_IP remote $GRE_VPS_MAIN_IP ttl 255 key $GRE_TUNNEL_KEY

# add $GRE_TUNNEL_BACKEND_IP as an IP for peer B on our newly created gre interface
ip addr add $GRE_TUNNEL_BACKEND_IP/30 dev $GRE_TUNNEL_INTERFACE_NAME

# bring the gre interface up
ip link set $GRE_TUNNEL_INTERFACE_NAME up

# setup the routing table if necessary
if ! grep -Fxq "$GRE_TUNNEL_RTTABLES_ID $GRE_TUNNEL_RTTABLES_NAME" /etc/iproute2/rt_tables
then
     echo "$GRE_TUNNEL_RTTABLES_ID $GRE_TUNNEL_RTTABLES_NAME" >> /etc/iproute2/rt_tables
fi

# the below command tells the system to forward any traffic, coming from an interface with an IP that belongs to the $GRE_TUNNEL_GATEWAY_IP/30 subnet, to the $GRE_TUNNEL_RTTABLES_NAME routing table
ip rule add from $GRE_TUNNEL_GATEWAY_IP/30 table $GRE_TUNNEL_RTTABLES_NAME

# the below commands forward any traffic coming from the $GRE_TUNNEL_RTTABLES_NAME routing table to $GRE_TUNNEL_GREVPS_IP, which is the peer A server
ip route add default via $GRE_TUNNEL_GREVPS_IP table $GRE_TUNNEL_RTTABLES_NAME

# tune the gre interface
tc qdisc replace dev $GRE_TUNNEL_INTERFACE_NAME root noqueue
ip link set $GRE_TUNNEL_INTERFACE_NAME txqueuelen 99999
```

`delGRE.sh` on Server B:
```
#!/bin/bash

# This script is placed on the backend server

#
# Variables
#

GRE_TUNNEL_INTERFACE_NAME="gre1"
GRE_TUNNEL_GATEWAY_IP="192.168.168.0"
GRE_TUNNEL_GREVPS_IP="192.168.168.1"
GRE_TUNNEL_BACKEND_IP="192.168.168.2"

GRE_TUNNEL_RTTABLES_NAME="GRETUN"

# ----------------------------------

ip route del default via $GRE_TUNNEL_GREVPS_IP table $GRE_TUNNEL_RTTABLES_NAME
ip rule del from $GRE_TUNNEL_GATEWAY_IP/30 table $GRE_TUNNEL_RTTABLES_NAME
ip addr del $GRE_TUNNEL_BACKEND_IP/30 dev $GRE_TUNNEL_INTERFACE_NAME
ip link set $GRE_TUNNEL_INTERFACE_NAME down
ip tunnel del $GRE_TUNNEL_INTERFACE_NAME
```

-----

## Notes

> 📌 each individual note is prefixed with a number. any dotted points are sub-points of a note.

1. On the GRE VPS [server A]:
  * It is recommended to use AlmaLinux
  * Make sure the system is up to date (dnf update)
  * Disable SELinux permanently
  * Add this to `/etc/security/limits.conf`:
    ```
    * soft nproc 2097152
    * hard nproc 2097152
    * soft nofile 2097152
    * hard nofile 2097152
    ```
  * Create the two files `/etc/systemd/system.conf.d/10-filelimit.conf` and `/etc/systemd/user.conf.d/10-filelimit.conf` with this content:
    ```
    [Manager]
    DefaultLimitNOFILE=2097152
    ```
    Note that you may need to create the `/etc/systemd/system.conf.d/` and `/etc/systemd/user.conf.d/` directories if they don't exist.
  * Reboot the VPS after updating the system & disabling SELinux

2. A bad provider for the GRE tunnel will cause packet loss.
     An example of that is Aeza.net. See https://lowendtalk.com/discussion/192513/aeza-sweden-and-probably-other-locations-network-issues

3. Setting the incorrect MTU for the gre (e.g. `gre1`) interface will cause packet loss and/or slow connectivity through the tunnel.
     It is recommended to always keep the default MTU values set by the provider and Linux.

4. If you are facing issues after setting the GRE tunnel up, try disabling the firewall (ufw/firewalld) on the destination (backend) server [if it's enabled].

     If this solves the problem but you would like to keep your firewall enabled, make sure the public IP address(es) of the GRE VPS and the private IP address(es) of the GRE VPS on the GRE tunnel (e.g. 192.168.168.1) are trusted on the firewall of the backend server.

5. ⚠️ If you have multiple IP addresses on your GRE VPS, make sure they are linked to the operating system first before attempting to involve them in a GRE tunnel! **This is super important! you can't magically start using an IP address when the operating system does not know about it.**

     For example, if your GRE VPS has the public IP address `a.b.c.d` as the main IP, and it also has `e.f.g.h` as an additional IP. Make sure the latter is configured on the GRE VPS system.

     On AlmaLinux this can be done by creating `/etc/sysconfig/network-scripts/ifcfg-eth0:1` and placing the following in it:
     ```
     DEVICE=eth0:1
     IPADDR=e.f.g.h
     NETMASK=[netmask here]
     GATEWAY=[gateway here]
     BOOTPROTO=none
     IPV4_FAILURE_FATAL=no
     PROXY_METHOD=none
     ```

     Make sure to replace everything with their proper values then restart the network service using `systemctl restart NetworkManager.service && sleep 5 && nmcli networking off && nmcli networking on`
     
     ⚠️ **NOTE:** You must restart your GRE tunnel (or all of your tunnels if you have multiple) after restarting the networking. This can be done by `./delGRE.sh && ./makeGRE.sh` [make sure to do the same for all your GRE tunnels if you have multiple scripts].

     You can absolutely do the same for all the IP addresses you would like to link. Just replace the `eth0:1` with `eth0:2`, etc.

6. If you have multiple IP addresses on the GRE VPS and you would like to use them to forward either to **multiple different backend servers** or to **the same backend server**, you can create multiple GRE tunnels.

     On both the GRE VPS (Server A) and the backend server (Server B), create new `makeGRE-2.sh` and `delGRE-2.sh` files so we can create new GRE setup scripts. The content of the files should be the same scripts that are at the top of this guide.

     Then edit this configurable part on the new scripts:
     ```
     GRE_TUNNEL_INTERFACE_NAME="gre1"
     GRE_TUNNEL_GATEWAY_IP="192.168.168.0"
     GRE_TUNNEL_GREVPS_IP="192.168.168.1"
     GRE_TUNNEL_BACKEND_IP="192.168.168.2"
     GRE_TUNNEL_KEY="1"
    
     GRE_TUNNEL_RTTABLES_ID="100"
     GRE_TUNNEL_RTTABLES_NAME="GRETUN"
     ```

     to be:

     ```
     GRE_TUNNEL_INTERFACE_NAME="gre2"
     GRE_TUNNEL_GATEWAY_IP="192.168.169.0" # NOTE: uses 169 instead of 168
     GRE_TUNNEL_GREVPS_IP="192.168.169.1" # NOTE: uses 169 instead of 168
     GRE_TUNNEL_BACKEND_IP="192.168.169.2" # NOTE: uses 169 instead of 168
     GRE_TUNNEL_KEY="2"
    
     GRE_TUNNEL_RTTABLES_ID="200"
     GRE_TUNNEL_RTTABLES_NAME="GRETUN2"
     ```

     then modify `GRE_VPS_IP` and `BACKEND_IP` to be the additional public IP of the GRE VPS and the IP of the new (or the same) backend server respectively. And make sure to modify the rest of the variables as well if necessary.

     ⚠️ **Also, super importantly,** make sure that the `iptables -F` line on the `makeGRE.sh` script of the GRE VPS is executed only once by ONLY ONE script. Otherwise the script of each GRE tunnel will keep clearing the iptables rules as they are executed, resulting in an unwanted behaviour.

     Now running `makeGRE-2.sh` on both the backend and the GRE VPS should set this up properly [make sure `makeGRE.sh` was run first because it has the `iptables -F` command which clears any unwanted iptables leftovers].
     
     Accessing the additional IP of the GRE VPS should forward the traffic to the same backend server that we set the main GRE tunnel up for. To confirm the setup, run this on the backend server:
     ```
     curl --interface 192.168.168.2 https://icanhazip.com
     curl --interface 192.168.169.2 https://icanhazip.com
     ```
     the first command should output the first IP address that we initially set up for the GRE tunnel. and the second command should output the additional IP address that we have just linked to the GRE tunnel.

     You can do the same for as many additional IP addresses as you want. Just create `makeGRE-3.sh` and `delGRE-3.sh`, and change the `192.168.169` part to something else like `192.168.170`

7. To make the GRE tunnel(s) persistent, create a file at `/etc/systemd/system/gretunnels.service` with the following content:

     ```
     [Unit]
     Description=GREInitService
     After=network.target

     [Service]
     Type=oneshot
     ExecStart=/root/makeGRE.sh
     ExecStop=/root/delGRE.sh
     User=root
     RemainAfterExit=yes

     [Install]
     WantedBy=multi-user.target
     ```

     Then run `systemctl daemon-reload`, `systemctl enable gretunnels.service`.

     This will:
     - make the GRE tunnel(s) automatically get created on the system boot.
     - make the management of the GRE tunnel(s) easier. just use `systemctl stop gretunnels.service` to delete the tunnel(s), and the same for `start`.

     Note that if you have multiple GRE tunnels setup by multiple scripts, it is better to create two scripts called `initGRE.sh` and `deinitGRE.sh`
     
     initGRE.sh:
     ```
     #!/bin/bash

     /root/makeGRE.sh
     /root/makeGRE-2.sh
     ```
     
     deinitGRE.sh:
     ```
     #!/bin/bash

     /root/delGRE-2.sh
     /root/delGRE.sh
     ```
     
     ⚠️ Notice how `deinitGRE` is in the inversed order of `initGRE` (the last executed `makeGRE` script is the first executed `delGRE` script).
     
     Then edit `/etc/systemd/system/gretunnels.service` to execute the newly created managing scripts instead:
     ```
     ExecStart=/root/initGRE.sh
     ExecStop=/root/deinitGRE.sh
     ```

8. If you want to make one of the GRE VPS IPs act like the primary IP of the backend server (i.e. all the internet requests on the backend server will see the GRE VPS IP as the public IP of the backend server):
     
     You will need to use these scripts **on server B [the backend server]** instead of the ones that were shown initially at the top of this whole guide [they are the same scripts with just a few additional commands]:
     
     makeGRE.sh on Server B (the backend server):
     ```
     #!/bin/bash
    
     # This script is placed on the backend server
    
     #
     # Variables
     #
    
     GRE_VPS_MAIN_IP="[the main public ip address of the gre vps here]" # NOTE: this is recommended to be the main public IP of the GRE VPS. even if you are trying to use an additional IP that belongs to the GRE VPS, it's nicer to put the main IP address here.
     BACKEND_IP="[backend server public ip address here]"
    
     GRE_TUNNEL_INTERFACE_NAME="gre1"
     GRE_TUNNEL_GATEWAY_IP="192.168.168.0"
     GRE_TUNNEL_GREVPS_IP="192.168.168.1"
     GRE_TUNNEL_BACKEND_IP="192.168.168.2"
     GRE_TUNNEL_KEY="1"
    
     GRE_TUNNEL_RTTABLES_ID="100"
     GRE_TUNNEL_RTTABLES_NAME="GRETUN"

     BACKEND_SERVER_MAIN_INTERFACE_NAME="eth0"
    
     # ----------------------------------

     # https://serverfault.com/questions/31170/how-to-find-the-gateway-ip-address-in-linux/31204#31204
     GATEWAY_IP=$(ip route show 0.0.0.0/0 dev $BACKEND_SERVER_MAIN_INTERFACE_NAME | cut -d\  -f3)

     # enable the gre kernel module [if needed]
     modprobe ip_gre
    
     # create a new gre tunnel
     # setting a `key` below is not necessary, however we do it in case there will be multiple gre tunnels with the same local and remote ips. iproute will consider this a duplicate tunnel (even with a different $GRE_TUNNEL_INTERFACE_NAME) and thus will fail to add it, unless a key is added.
     ip tunnel add $GRE_TUNNEL_INTERFACE_NAME mode gre local $BACKEND_IP remote $GRE_VPS_MAIN_IP ttl 255 key $GRE_TUNNEL_KEY
    
     # add $GRE_TUNNEL_BACKEND_IP as an IP for peer B on our newly created gre interface
     ip addr add $GRE_TUNNEL_BACKEND_IP/30 dev $GRE_TUNNEL_INTERFACE_NAME
    
     # bring the gre interface up
     ip link set $GRE_TUNNEL_INTERFACE_NAME up
    
     # setup the routing table if necessary
     if ! grep -Fxq "$GRE_TUNNEL_RTTABLES_ID $GRE_TUNNEL_RTTABLES_NAME" /etc/iproute2/rt_tables
     then
          echo "$GRE_TUNNEL_RTTABLES_ID $GRE_TUNNEL_RTTABLES_NAME" >> /etc/iproute2/rt_tables
     fi
    
     # the below command tells the system to forward any traffic, coming from an interface with an IP that belongs to the $GRE_TUNNEL_GATEWAY_IP/30 subnet, to the $GRE_TUNNEL_RTTABLES_NAME routing table
     ip rule add from $GRE_TUNNEL_GATEWAY_IP/30 table $GRE_TUNNEL_RTTABLES_NAME
    
     # the below commands forward any traffic coming from the $GRE_TUNNEL_RTTABLES_NAME routing table to $GRE_TUNNEL_GREVPS_IP, which is the peer A server
     ip route add default via $GRE_TUNNEL_GREVPS_IP table $GRE_TUNNEL_RTTABLES_NAME

     # dns servers are required otherwise all dns resolutions will fail
     # the reason this happens is because in a command below we are about to route all the traffic through the gre tunnel, this also includes DNS requests
     echo 'nameserver 1.1.1.1' > /etc/resolv.conf
     echo 'nameserver 1.0.0.1' >> /etc/resolv.conf

     # finally cut over our routing
     # NOTE: this will cut all access to your original BACKEND IP!

     # route all the traffic through the gre tunnel. except for $GRE_VPS_MAIN_IP, which still will be routed through the original gateway of server B [this server] instead.
     # the reason we put this exception is because $GRE_VPS_MAIN_IP is used as the gre peer address for our tunnel (its the IP that connects this server to server A). we need it to be accessible so our gre tunnel can function properly.
     # `metric 0` means the new `default` route takes the highest priority [so it can replace the original default route]
     ip route add $GRE_VPS_MAIN_IP via $GATEWAY_IP dev $BACKEND_SERVER_MAIN_INTERFACE_NAME onlink
     ip route add default via $GRE_TUNNEL_GREVPS_IP metric 0
    
     # tune the gre interface
     tc qdisc replace dev $GRE_TUNNEL_INTERFACE_NAME root noqueue
     ip link set $GRE_TUNNEL_INTERFACE_NAME txqueuelen 99999
     ```
     
     delGRE.sh on Server B (the backend server):
     ```
     #!/bin/bash

     # This script is placed on the backend server
    
     #
     # Variables
     #

     GRE_VPS_MAIN_IP="[the main public ip address of the gre vps here]" # NOTE: this is recommended to be the main public IP of the GRE VPS. even if you are trying to use an additional IP that belongs to the GRE VPS, it's nicer to put the main IP address here.
    
     GRE_TUNNEL_INTERFACE_NAME="gre1"
     GRE_TUNNEL_GATEWAY_IP="192.168.168.0"
     GRE_TUNNEL_GREVPS_IP="192.168.168.1"
     GRE_TUNNEL_BACKEND_IP="192.168.168.2"
    
     GRE_TUNNEL_RTTABLES_NAME="GRETUN"

     BACKEND_SERVER_MAIN_INTERFACE_NAME="eth0"
    
     # ----------------------------------

     # https://serverfault.com/questions/31170/how-to-find-the-gateway-ip-address-in-linux/31204#31204
     GATEWAY_IP=$(ip route show 0.0.0.0/0 dev $BACKEND_SERVER_MAIN_INTERFACE_NAME | cut -d\  -f3)

     ip route del default via $GRE_TUNNEL_GREVPS_IP metric 0
     ip route del $GRE_VPS_MAIN_IP via $GATEWAY_IP dev $BACKEND_SERVER_MAIN_INTERFACE_NAME onlink
    
     ip route del default via $GRE_TUNNEL_GREVPS_IP table $GRE_TUNNEL_RTTABLES_NAME
     ip rule del from $GRE_TUNNEL_GATEWAY_IP/30 table $GRE_TUNNEL_RTTABLES_NAME
     ip addr del $GRE_TUNNEL_BACKEND_IP/30 dev $GRE_TUNNEL_INTERFACE_NAME
     ip link set $GRE_TUNNEL_INTERFACE_NAME down
     ip tunnel del $GRE_TUNNEL_INTERFACE_NAME
     ```
     
     As for the scripts of server A [the GRE VPS], leave them unchanged.

9. If you want to forward just certain ports instead of forwarding all the traffic:
    
   In the `makeGRE.sh` script of Server A, replace:
   ```
   iptables -t nat -A PREROUTING -d $GRE_VPS_IP -j DNAT --to-destination $GRE_TUNNEL_BACKEND_IP
   ```
   with:
   ```
   iptables -t nat -A PREROUTING -d $GRE_VPS_IP -p [protocol here] -m [protocol here] --dport [port here] -j DNAT --to-destination $GRE_TUNNEL_BACKEND_IP
   ```

   for example, to forward all the data to a Webserver (Port TCP 80) we have to put:
   ```
   iptables -t nat -A PREROUTING -d $GRE_VPS_IP -p tcp -m tcp --dport 80 -j DNAT --to-destination $GRE_TUNNEL_BACKEND_IP
   ```

   Also make sure to edit the `delGRE.sh` script of Server A and add the same iptables command, but with replacing the `-A` argument with `-D` to undo the iptables rule.
   
   For example:
   ```
   iptables -t nat -D PREROUTING -d $GRE_VPS_IP -p tcp -m tcp --dport 80 -j DNAT --to-destination $GRE_TUNNEL_BACKEND_IP
   ```

10. Reboot the GRE VPS (and preferably but not necessarily the backend server[s] too) after setting up or modifying any GRE tunnels to ensure that no unneeded leftovers are there. This really makes a difference most of the time.

## ⚠️ An important note if you are using BuyVM as your GRE VPS + a DDoS protected IP (or more) from them

Make sure that the main IP address of your BuyVM VPS is the normal non-DDoS protected IP address. You can set the main IP address through the BuyVM Stallion panel.

Also make sure to use that same normal non-DDoS protected IP address as the value of the `GRE_VPS_MAIN_IP` variable in the scripts.

The main reason we do this is to avoid getting the IP address of our backend server from getting blocked by the BuyVM (Path.net) DDoS protection.

> From https://wiki.buyvm.net/doku.php/gre_tunnel:
> 
> You will always want to form your GRE with your unfiltered IP address for all GRE tunnels to make sure you don't run into any sort of MTU issues or trigger the DDOS protection.

Also as an additional precaution step, you can go to the DDoS protection panel on your BuyVM Stallion and add a firewall rule like this:
```
Source IP Address: [the public IP of the backend server]/32
Protocol: ALL (All Protocols)
Action: Allow
```

## Inspiration
- https://community.hetzner.com/tutorials/linux-setup-gre-tunnel
- https://wiki.buyvm.net/doku.php/gre_tunnel
- https://wiki.buyvm.net/doku.php/gre_tunnel:docker (mainly only for the formatting of the shell scripts)
- https://richardbernecker.com/configuring-a-persistent-gre-tunnel-via-systemd/
- https://github.com/klaver/sysctl
