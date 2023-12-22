from ssdp_server import UPNPSSDPServer, logger
from uuid import uuid4
from http_server import UPNPHTTPServer
import configparser
import sys
from version import Version
import time
from optparse import OptionParser


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


def parse_options():
    """
    Parse options from the key words.
    :return: options given.
        This structure contains .config_file with the name of the configuration file.
    """

    parser = OptionParser()
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true",
                      help="Add this option to make server running verbose. "
                           "Without this option only errors will be logged.")
    parser.add_option("-c", "--config", default="configuration.ini", help="Configuration file path")
    (options, args) = parser.parse_args()

    return options


if __name__ == '__main__':

    options = parse_options()

    print("Revealer friendly SSDP server: version {}".format(Version.full))

    config_file_path = options.config
    http_port = 5050
    time_after_error_sec = 3
    if options.verbose:
        # if verbose mode is requested - set logger level to info
        logger.setLevel(20)
    else:
        # if we should be quiet - set it to errors
        logger.setLevel(40)

    device_uuid = uuid4()

    config = configparser.ConfigParser(allow_no_value=True)
    try:
        with open(config_file_path) as f:
            config.read_file(f)
    except IOError as e:
        logger.fatal("Configuration file '%s' could not be opened: %r" % (config_file_path, e))
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
                         server=server_data, location_port=http_port)
    while True:
        # try to create http server and start
        http_server = UPNPHTTPServer(http_port,
                                     config['MAIN']['friendly_name'],
                                     config['MAIN']['manufacturer'],
                                     config['MAIN']['manufacturer_url'],
                                     config['MAIN']['model_description'],
                                     config['MAIN']['model_name'],
                                     config['MAIN']['model_number'],
                                     config['MAIN']['model_url'],
                                     config['MAIN']['serial_number'],
                                     device_uuid,
                                     config['MAIN']['presentation_url'],
                                     redirect_port=config['MAIN']['redirect_port'])
        http_server.start()
        result = ssdp_server.run()

        if result == 1:
            logger.error("SSDP server could not be started because it can't join the multicast group"
                         " on any interfaces.\n"
                         "It will be restarted in {} seconds.".format(time_after_error_sec))
            # stop http server to start again later
            http_server.server.shutdown()
            del http_server
            # wait for some time to try again
            time.sleep(time_after_error_sec)
