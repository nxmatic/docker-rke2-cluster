podman machine ssh <<EoS
: Create bridge interface for VLAN 10
nmcli connection add type vlan con-name vlan10 dev enp0s1 id 10 # ip4 172.25.2.1
nmcli connection add type bridge con-name vlan10-bridge ifname vlan-bridge ipv4.addresses 172.25.1.1/24
nmcli connection add type bridge-slave con-name vlan10-bridge-slave ifname enp0s1.10 master vlan-bridge
EoS
: Create VLAN 20
: podman machine ssh nmcli connection add type vlan con-name vlan20 dev enp0s1 id 20 # ip4 172.25.2.1/24 gw4 172.25.2.1
