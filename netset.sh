#!/bin/bash

usage="Usage:
    $(basename "$0") [-h | --help] [--interface <interface> 
                                    --dhcp <0|1> --ipv4 <address> 
                                    --netmask <address> --gateway <address>]

     -h, --help                 show this help
     --interface <interface>    name of the interface to change network
                                settings of
     --dhcp <0|1>               setting DHCP usage flag: 0 - use static IP,
                                1 - use dynamic IP from DHCP server
     --ipv4 <address>           IPv4 address for the interface (will be 
                                used if static configuration method is
                                chosen with --dhcp 0)
     --netmask <address>        Network mask address for the interface 
                                (will be used if static configuration
                                method is chosen with --dhcp 0)
     --gateway <address>        Default gateway address for the interface 
                                (will be used if static configuration 
                                method is chosen with --dhcp 0)

Examples:
   $0 --interface eth0 --dhcp 1 
   $0 --interface eth0 --dhcp 0 --ipv4 192.168.1.2 --netmask 255.255.255.0 --gateway 192.168.1.1
"
# parse arguments
for (( i=1; i<=$#; i++));
do
    if [ "${!i}" = "--interface" ]
    then
        j=$((i+1))
        interface="${!j}"
    elif [ "${!i}" = "--ipv4" ]
    then
        j=$((i+1))
        ipv4="${!j}"
    elif [ "${!i}" = "--netmask" ]
    then
        j=$((i+1))
        netmask="${!j}"
    elif [ "${!i}" = "--dhcp" ]
    then
        j=$((i+1))
        dhcp="${!j}"
    elif [ "${!i}" = "--gateway" ]
    then
        j=$((i+1))
        gateway="${!j}"
    elif [ "${!i}" = "--help" ]
    then
        echo "$usage"
        exit
    elif [ "${!i}" = "-h" ]
    then
        echo "$usage"
        exit
    fi
done

#echo "interface=$interface ipv4=$ipv4 netmask=$netmask dhcp=$dhcp gateway=$gateway"

if [ "$USER" != "root" ]
  then
   echo "Can't run network update script. Must be root."
  exit 1
fi

function IsNMRunning ()
{
  if systemctl is-active --quiet NetworkManager; then
    echo "NetworkManager is running."
      return 0
  else
    echo "NetworkManager is not running."
      return 1
  fi
}

function IsNetplanActive ()
{
  if command -v netplan &> /dev/null; then
    echo "Netplan is installed."
    return 0
  else  
    echo "Netplan is not installed."
    return 1
  fi
}

function ConvertNetmask ()
{
  PARAMS=${netmask}
  BARRAY=({0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1})
  NETMASK=${PARAMS#* }
  NETMASK=${NETMASK//./ }
  BINARY_NETMASK=$(for octet in $NETMASK; do echo -n ${BARRAY[octet]}" "; done)
  BIN_MASK_SEP1=${BINARY_NETMASK//1/1 }
  BINARY_MASK_ARRAY=( ${BIN_MASK_SEP1//0/0 } )
  BITS_COUNT=0
  for i in ${BINARY_MASK_ARRAY[@]}
  do
    [ "$i" == "1" ] && BITS_COUNT=$((BITS_COUNT + 1))
  done
  BITMASK=${BITS_COUNT}
}

function SetDynamicIP ()
{
  # Remove "default" route
  ip route flush default

  # Remove IPv4 address
  ip -4 addr flush dev ${interface}

  # Setup IPv4 dynamic address
  dhclient -4 ${interface}
}

function SetStaticIP ()
{
  # Remove "default" route
  #ip route del default
  ip route flush default

  # Remove IPv4 address
  ip addr flush dev ${interface}

  # Setup IPv4 static address
  ip addr add ${ipv4}/${netmask} dev ${interface}

  # Add default route
  ip route add default dev ${interface} via ${gateway}
#  exit 0
}

function AddStaticConfigNetplan ()
{

  rm -f /etc/netplan/*

  cat << EOF >> /etc/netplan/networkd-manager-${interface}.yaml
network:
  version: 2
  ethernets:
    ${interface}:
      dhcp4: no
      dhcp6: no
      addresses: [ ${ipv4}/${BITMASK} ]
      gateway4: ${gateway}
EOF
}

function AddDynamicConfigNetplan ()
{
  rm -f /etc/netplan/*

cat << EOF >> /etc/netplan/networkd-manager-${interface}.yaml
network:
  version: 2
  ethernets:
    ${interface}:
      dhcp4: true
EOF
}

function AddDinamicConfigNM ()
{
  rm -f /etc/netplan/*

  find /etc/NetworkManager/system-connections/ -type f -iname "*${interface}*" -delete
  nmcli connection add type ethernet ifname ${interface} con-name ${interface} ipv4.method auto autoconnect yes
}

function AddStaticConfigNM ()
{
  find /etc/NetworkManager/system-connections/ -type f -iname "*${interface}*" -delete
  nmcli connection add type ethernet ifname ${interface} con-name ${interface} ipv4.method manual ipv4.addresses ${ipv4}/${BITMASK} ipv4.gateway ${gateway} autoconnect yes
  rm -f /etc/netplan/*

}

if [[ "${dhcp}" == "1" && IsNMRunning ]]; then
    SetDynamicIP
    AddDinamicConfigNM
  else
    if [[ "${dhcp}" == "0" && IsNMRunning ]]; then
        echo "Dynam"
        ConvertNetmask
        SetStaticIP
        AddStaticConfigNM
  fi
fi

