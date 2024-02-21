#!/bin/sh

# if this service is already in work - stop it
systemctl stop pyssdp_server
systemctl disable pyssdp_server

# recreate webroot source folder if exist
rm -rf /usr/lib/pyssdp_server/webroot

# copy folder with service source files
cp -a ./ /usr/lib/pyssdp_server

# copy 
cp pyssdp_server.service /etc/systemd/system

# enable service
systemctl enable pyssdp_server
systemctl start pyssdp_server
