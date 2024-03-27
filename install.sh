#!/bin/sh

# if this service is already in work - stop it
if [ -e /etc/systemd/system/pyssdp_server.service ]
then
    systemctl stop pyssdp_server
    systemctl disable pyssdp_server
fi

# recreate webroot source folder if exist
rm -rf /usr/lib/pyssdp_server/webroot

# copy folder with service source files
cp -a ./ /usr/lib/pyssdp_server

# create venv with requirements
cd /usr/lib/pyssdp_server
python3 -m venv venv
venv/bin/python3 -m pip install --upgrade pip
venv/bin/python3 -m pip install -r requirements.txt

# copy 
cp pyssdp_server.service /etc/systemd/system

# enable service
systemctl enable pyssdp_server
systemctl start pyssdp_server
