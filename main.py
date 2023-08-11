from ssdp_server import UPNPSSDPServer, logger
from uuid import uuid4
from http_server import UPNPHTTPServer
import configparser
import sys
from version import Version


def check_required_field(config, logger, section_name, field_name):
    if field_name not in config[section_name]:
        logger.fatal("Error: no '%s' field in [%s] section of config file. \
                     This field is required" % (field_name, section_name))
        sys.exit()
    else:
        if config[section_name][field_name] == "":
            logger.fatal("Error: '%s' field in [%s] section of config file is empty. \
                         This field is required" % (field_name, section_name))
            sys.exit()
    return


def check_optional_field(config, logger, section_name, field_name):
    if field_name not in config[section_name]:
        logger.warning("Warning: no '%s' field in [%s] section of config file. \
                       An empty string will be sent" % (field_name, section_name))
        config[section_name][field_name] = ""
    return


if __name__ == '__main__':
    print("Revealer friendly SSDP server: version {}".format(Version.full))

    filename = 'configuration.ini'
    http_port = 80
    logger.setLevel(30)
    device_uuid = uuid4()

    config = configparser.ConfigParser(allow_no_value=True)
    try:
        with open(filename) as f:
            config.read_file(f)
    except IOError as e:
        logger.fatal("Configuration file '%s' could not be opened: %r" % (filename, e))
        sys.exit()

    # Check sections
    if 'MAIN' not in config:
        logger.fatal("Error: configuration file does not have a [MAIN] section")
        sys.exit()
    if 'SERVER' not in config:
        logger.fatal("Error: configuration file does not have a [SERVER] section")
        sys.exit()

    # Check required fields
    check_required_field(config, logger, 'MAIN', 'friendly_name')
    check_required_field(config, logger, 'SERVER', 'product')
    check_required_field(config, logger, 'SERVER', 'product_version')

    # Check other fields
    config_main_labels = ['manufacturer', 'manufacturer_url',
                          'model_description', 'model_name',
                          'model_number', 'model_url', 'model_number',
                          'presentation_url']
    for label in config_main_labels:
        check_optional_field(config, logger, 'MAIN', label)
    config_server_labels = ['os', 'os_version']
    for label in config_server_labels:
        check_optional_field(config, logger, 'SERVER', label)

    http_server = UPNPHTTPServer(http_port,
                                 config['MAIN']['friendly_name'],
                                 config['MAIN']['manufacturer'],
                                 config['MAIN']['manufacturer_url'],
                                 config['MAIN']['model_description'],
                                 config['MAIN']['model_name'],
                                 config['MAIN']['model_number'],
                                 config['MAIN']['model_url'],
                                 config['MAIN']['model_number'],
                                 device_uuid,
                                 config['MAIN']['presentation_url'])
    http_server.start()

    usn = 'uuid:{}::upnp:rootdevice'.format(device_uuid)

    # format: SERVER: lwIP/1.4.1 UPnP/2.0 8SMC5-USB/4.7.7
    os = config['SERVER']['os']
    os_version = config['SERVER']['os_version']
    product = config['SERVER']['product']
    product_version = config['SERVER']['product_version']
    server_data = "{}/{} UPnP/2.0 {}/{}".format(os, os_version, product, product_version)

    ssdp_server = UPNPSSDPServer()
    ssdp_server.register('local',
                         usn,
                         'upnp:rootdevice',
                         '',  # will be set while constructing ssdp messages
                         server=server_data)
    ssdp_server.run()
