#!/bin/sh

if [ -e /etc/systemd/system/pyssdp_server.service ]
then
    echo "Stopping and disabling PySSDP Server service..."
    # disable service
    systemctl stop pyssdp_server
    systemctl disable pyssdp_server


    echo "Removing its files..."
    # remove service source files from the system
    rm -rf /usr/lib/pyssdp_server
    rm -rf /etc/systemd/system/pyssdp_server.service

    echo "PySSDP Server is now uninstalled from the system."
else
    echo "PySSDP Server is not installed."
fi
