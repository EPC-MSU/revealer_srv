#!/bin/sh -u

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

echo "interface=$interface ipv4=$ipv4 netmask=$netmask dhcp=$dhcp gateway=$gateway"

# TODO: add network setting function here

