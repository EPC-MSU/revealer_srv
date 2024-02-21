#!/bin/sh

# disable service
systemctl stop pyssdp_server
systemctl disable pyssdp_server

# remove service source files from the system
rm -rf /usr/lib/pyssdp_server
rm -rf /etc/systemd/system/pyssdp_server.service
