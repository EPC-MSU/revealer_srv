#!/bin/sh

echo "Starting the installation of PySSDP Server..."
# if this service is already in work - stop it
if [ -e /etc/systemd/system/pyssdp_server.service ]
then
    echo "PySSDP Server is already installed so it will now be reinstalled."
    systemctl stop pyssdp_server
    systemctl disable pyssdp_server
fi

# recreate webroot source folder if exist
rm -rf /usr/lib/pyssdp_server/webroot

# copy folder with service source files
cp -a ./ /usr/lib/pyssdp_server

echo "Copying server file to the /usr/lib/pyssdp_server/ directory..."
# remove venv if exist
rm -rf /usr/lib/pyssdp_server/venv

echo "Creating a virtual environment..."
# create venv with requirements
cd /usr/lib/pyssdp_server
python3 -m venv venv
venv/bin/python3 -m pip install --upgrade pip
venv/bin/python3 -m pip install -r requirements.txt

echo "Creating and starting a systemd service..."
# copy
cp pyssdp_server.service /etc/systemd/system

# enable service
systemctl enable pyssdp_server
systemctl start pyssdp_server

