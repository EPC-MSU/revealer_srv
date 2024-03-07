from lib.ssdp import SSDPServer, logger
import socket
import random
from platform import system
from email.utils import formatdate
import ifaddr
from errno import ENOPROTOOPT
import sys
import ipaddress
# TODO: maybe we can do it without another external module?
import getmac
import uuid

import subprocess

SSDP_PORT = 1900
SSDP_ADDR = '239.255.255.250'
bad_interfaces = []

RESULT_OK = 0
RESULT_ERROR = 1

NAMESPACE_PYSSDP_SERVER = uuid.UUID("714c3c93-8f5b-4034-a5c5-89d9e94e8a19")


class DeviceInterfaces:

    def __init__(self):
        self.adapters = ifaddr.get_adapters(include_unconfigured=True)
        self.mac_addresses_dict = {}

        for adapter in self.adapters:
            name = adapter.name
            # if we are on win system ifaddr return UUID of the adapter as its name so if mac-address is None - try
            # to get uuid from name itself
            if len(name[1:len(name) - 1]) == 36 and system() == 'Windows':
                uuid_name = name[1:len(name) - 1].lower()
                mac_address = uuid_name[24:36]
            else:
                mac_address = getmac.get_mac_address(interface=name)
                if mac_address is None:
                    uuid_name = None
                else:
                    adapter.hw_address = mac_address
                    # uuid_name = uuid.UUID(int=int("0x" + mac_address.replace(":", ""), 16), version=4)
                    uuid_name = str(uuid.uuid3(NAMESPACE_PYSSDP_SERVER, mac_address))

            self.mac_addresses_dict[name] = {"mac": mac_address, "uuid": uuid_name}

    def update(self):
        self.adapters = ifaddr.get_adapters(include_unconfigured=True)
        self.mac_addresses_dict = {}

        for adapter in self.adapters:
            name = adapter.name
            # if we are on win system ifaddr return UUID of the adapter as its name so if mac-address is None - try
            # to get uuid from name itself
            if len(name[1:len(name) - 1]) == 36 and system() == 'Windows':
                uuid_name = name[1:len(name) - 1].lower()
                mac_address = uuid_name[24:36]
            else:
                mac_address = getmac.get_mac_address(interface=name)
                if mac_address is None:
                    uuid_name = None
                else:
                    adapter.hw_address = mac_address
                    # uuid_name = uuid.UUID(int=int("0x" + mac_address.replace(":", ""), 16), version=4)
                    uuid_name = str(uuid.uuid3(NAMESPACE_PYSSDP_SERVER, mac_address))

            self.mac_addresses_dict[name] = {"mac": mac_address, "uuid": uuid_name}

    def get_name_by_ip(self, ip_addr: str):
        """

        :return:
        """

        for adapter in self.adapters:
            for ip in adapter.ips:
                if not isinstance(ip.ip, str):
                    # we don't need ipv6
                    continue

                if ip.ip == ip_addr:
                    return adapter.name

        # if we couldn't find any adapters with this ip...
        return None

    def get_uuid_by_ip(self, ip_addr: str):
        """

        :return:
        """

        name = self.get_name_by_ip(ip_addr=ip_addr)

        if name is None:
            return None

        try:
            uuid_name = self.mac_addresses_dict[name]['uuid']
            return uuid_name
        except KeyError:
            return None

    def get_ip_by_name(self, name: str):
        """

        :param name:
        :return:
        """
        for adapter in self.adapters:
            if name == adapter.name:
                for ip in adapter.ips:
                    if not isinstance(ip.ip, str):
                        # we don't need ipv6
                        continue

                    return ip.ip

        # if we couldn't find any adapters with this ip...
        return None

    def get_ip_by_uuid(self, device_uuid: str):
        """

        :return:
        """

        for name in self.mac_addresses_dict:
            uuid_name = self.mac_addresses_dict[name]['uuid']
            if uuid_name == device_uuid:
                ip_addr = self.get_ip_by_name(name=name)
                return ip_addr

        return None


class UPNPSSDPServer(SSDPServer):
    def __init__(self, change_settings_script_path='', password=''):
        SSDPServer.__init__(self)

        self.change_settings_script_path = change_settings_script_path
        self.password = password

        self.adapters = ifaddr.get_adapters()
        self.interfaces = DeviceInterfaces()

    def _setup_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if hasattr(socket, "SO_REUSEPORT"):
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except socket.error as le:
                # RHEL6 defines SO_REUSEPORT but it doesn't work
                if le.errno != ENOPROTOOPT:
                    raise

        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        if system() == 'Linux':
            result = self._setup_socket_on_linux()
        else:
            result = self._setup_socket_non_linux()

        return result

    def _setup_socket_on_linux(self):
        logger.info("Linux system. Will try to join multicast on interface 0.0.0.0")
        interface = socket.inet_aton('0.0.0.0')
        try:
            ssdp_addr = socket.inet_aton(SSDP_ADDR)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, ssdp_addr + interface)
            logger.info('Joined multicast on interface 0.0.0.0')
            return RESULT_OK
        except socket.error as msg:
            logger.warn("Failed to join multicast on interface 0.0.0.0: %r" % msg)
            return RESULT_ERROR

    def _setup_socket_non_linux(self):
        logger.info("Not a Linux system. Joining multicast on all interfaces")
        if_count = 0
        self.adapters = ifaddr.get_adapters()
        for adapter in self.adapters:
            for ip in adapter.ips:
                if not isinstance(ip.ip, str):
                    continue

                if ip.ip == '127.0.0.1':
                    continue

                if_count += 1
                interface = socket.inet_aton(ip.ip)
                try:
                    ssdp_addr = socket.inet_aton(SSDP_ADDR)
                    self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, ssdp_addr + interface)
                    logger.info('Joined multicast on interface %s/%d' % (ip.ip, ip.network_prefix))
                except socket.error as msg:
                    logger.warn("Failed to join multicast on interface %s. This interface will be ignored. %r"
                                % (ip.ip, msg))
                    bad_interfaces.append(ip.ip)
                    continue

        if if_count == len(bad_interfaces):
            logger.warn("Failed to join multicast on all interfaces. Server won't be able to send NOTIFY messages.")
            return RESULT_ERROR
        else:
            # we joined multicast on at least one interface so return 0
            return RESULT_OK

    def run(self):

        result = self._setup_socket()

        if result == RESULT_ERROR:
            # if we are not able to join multicast on any interfaces - we want to try again
            return result

        try:
            self.sock.bind(('', SSDP_PORT))
        except OSError as e:
            logger.fatal("""Error creating ssdp server on port %d. Please check that the port is not in use: %r"""
                         % (SSDP_PORT, e))
            sys.exit()
        self.sock.settimeout(1)

        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                self.datagram_received(data, addr)
            except socket.timeout:
                continue
        self.shutdown()
        return RESULT_ERROR

    def _create_location_link(self, host_ip: str) -> str:
        """
        Method for creating LOCATION link to send to specific host.
        :param host_ip: str
          IP-address of the host to whom we should send our discovery answer.
        :return:
        """

        location_link = '/Basic_info.xml'

        self.adapters = ifaddr.get_adapters()
        for adapter in self.adapters:
            for ip in adapter.ips:
                if not isinstance(ip.ip, str):
                    continue
                #if ip.ip == "127.0.0.1":
                    #continue
                network = ipaddress.IPv4Network(ip.ip + "/" + str(ip.network_prefix), strict=False)
                if ipaddress.ip_address(host_ip) in ipaddress.ip_network(network):
                    # For correct windows network search
                    # from the same PC

                    # If there is a LOCATION field, the link needs to be correct
                    # for windows to show the device
                    location_link = 'http://{}:{}/Basic_info.xml'.format(ip.ip, self.location_port)

        return location_link

    def discovery_request(self, headers, host_port):

        (host, port) = host_port

        logger.debug('Discovery request from (%s,%d) for %s' % (host, port, headers['st']))
        logger.debug(headers['st'][0:5])

        device_uuid = self.known

        # Do we know about this service?
        for i in self.known.values():
            if i['MANIFESTATION'] == 'remote':
                continue
            if headers['st'] == 'ssdp:all' and i['SILENT']:
                continue
            if i['ST'] == headers['st'] or headers['st'] == 'ssdp:all' or headers['st'][0:5] == 'uuid:':

                logger.warning('Discovery request 2 from (%s,%d) for %s' % (host, port, headers['st']))

                response = ['HTTP/1.1 200 OK']

                usn = None
                uuid_st = None
                device_ip = None
                result = RESULT_OK
                for k, v in i.items():
                    if k == 'USN':
                        usn = v
                        uuid_st = self.exctract_uuid_st_from_usn(usn=usn)
                        device_uuid = uuid_st[5:].lower()
                        self.interfaces.update()
                        device_ip = self.interfaces.get_ip_by_uuid(device_uuid=device_uuid)

                    if k == 'LOCATION':
                        v = self._create_location_link(host_ip=host)
                        continue

                    if k not in ('MANIFESTATION', 'SILENT', 'HOST'):
                        response.append('%s: %s' % (k, v))

                # create location link with found device ip from adapter list for this usn
                if device_ip is not None:
                    response.append('LOCATION: http://%s:%s/Basic_info.xml' % (device_ip, self.location_port))
                    self.known[usn]['LOCATION'] = 'http://%s:%s/Basic_info.xml' % (device_ip, self.location_port)
                else:
                    # TODO: we don't need device without ip i think?
                    continue

                if device_ip in bad_interfaces:
                    continue

                # check if special uuid was requested
                if not uuid_st or (headers['st'][0:5] == 'uuid:' and headers['st'] != uuid_st):
                    # send nothing
                    continue
                elif uuid_st is not None and headers['st'] == uuid_st:
                    # we received discovery specifically for us - it may be our MIPAS request to change network settings
                    print(f"Received MIPAS!!!'{headers['mipas']}'")
                    print(self.parse_mipas_field(headers['mipas']))
                    # check if path to net set script is valid
                    if len(self.change_settings_script_path) > 0:
                        result = self.set_net_settings(netset=self.parse_mipas_field(headers['mipas']),
                                                       adapter=self.get_adapter_by_uuid_st(uuid_st=uuid_st))
                        print("result =", result)
                    else:
                        result = RESULT_ERROR

                if usn and result == RESULT_OK and device_ip != "127.0.0.1":
                    response.append('DATE: %s' % formatdate(timeval=None, localtime=False, usegmt=True))

                    # we need to make revealer know that we support changing network settings via multicast (MIPAS)
                    response.append('MIPAS:')

                    response.extend(('', ''))
                    delay = random.randint(0, int(headers['mx']))

                    self.send_it('\r\n'.join(response), (host, port), delay, usn)

                    # NOTIFY - to make sure the response reaches client
                    # self.notify_from_all_interfaces(usn)
                    # self.do_notify(usn)
                    self.do_notify_on_interface(usn, device_ip)

    def do_notify_on_interface(self, usn, ip_addr):
        if_addr = socket.inet_aton(ip_addr)
        try:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, if_addr)
            logger.info('Set interface to %s' % ip_addr)
        except socket.error as msg:
            logger.warn("Failure connecting to interface %s: %r" % (ip_addr, msg))
            return

        self.do_notify(usn)

    def notify_from_all_interfaces(self, usn):
        self.adapters = ifaddr.get_adapters()
        for adapter in self.adapters:

            for ip in adapter.ips:
                if not isinstance(ip.ip, str):
                    continue

                if ip.ip in bad_interfaces:
                    continue

                if_addr = socket.inet_aton(ip.ip)
                try:
                    self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, if_addr)
                    logger.info('Set interface to %s' % ip.ip)
                except socket.error as msg:
                    logger.warn("Failure connecting to interface %s: %r" % (ip.ip, msg))
                    continue

                # format: LOCATION: http://172.16.130.67:80/Basic_info.xml
                url = 'http://{}:{}/Basic_info.xml'.format(ip.ip, self.location_port)
                self.known[usn]['LOCATION'] = url

                self.do_notify(usn)

    # Переопределения для более удобного логирования
    def send_it(self, response, destination, delay, usn):
        logger.info('HTTP/1.1 200 OK response delayed by %ds to %r' % (delay, destination))
        try:
            self.sock.sendto(response.encode(), destination)
        except (AttributeError, socket.error) as msg:
            logger.warning("Failure sending out HTTP/1.1 200 OK response: %r" % msg)

    def do_notify(self, usn):
        """Do notification"""

        if self.known[usn]['SILENT']:
            return
        logger.info('NOTIFY response for %s' % usn)

        resp = [
            'NOTIFY * HTTP/1.1',
            'HOST: %s:%d' % (SSDP_ADDR, SSDP_PORT),
            'NTS: ssdp:alive',
        ]
        stcpy = dict(self.known[usn].items())
        stcpy['NT'] = stcpy['ST']
        del stcpy['ST']
        del stcpy['MANIFESTATION']
        del stcpy['SILENT']
        del stcpy['HOST']
        del stcpy['last-seen']

        resp.extend(map(lambda x: ': '.join(x), stcpy.items()))
        resp.append("MIPAS:")
        resp.extend(('', ''))
        logger.debug('do_notify content', resp)
        try:
            self.sock.sendto('\r\n'.join(resp).encode(), (SSDP_ADDR, SSDP_PORT))
            self.sock.sendto('\r\n'.join(resp).encode(), (SSDP_ADDR, SSDP_PORT))
        except (AttributeError, socket.error) as msg:
            logger.warning("Failure sending out NOTIFY response: %r" % msg)

    @staticmethod
    def exctract_uuid_st_from_usn(usn):
        """
        Extract "uuid:{device-uuid}" line from USN field value with structure "uuid:{device-uuid}::upnp:rootdevice"
        :param usn:
        :return:
        """

        return usn[0:41]

    @staticmethod
    def parse_mipas_field(value):
        """
        MIPAS (multicast IP address setting) field parsing method.

        It has structure:
          {password};{dhcp_enabled};{ip-address};{net-mask};{gateway-address};
        :param value:
        :return: netset: dict - dictionary with new requested settings
        """

        params = value.split(';')

        if len(params) >= 5:
            netset = {"password": params[0], "dhcp_enabled": params[1],"ip-address": params[2],
                      "net-mask": params[3], "gw-address": params[4]}
            return netset
        else:
            logger.error("Incorrect MIPAS field structure: {}. "
                         "It should be: '<password>;<dhcp_enabled>;<ip-address>;<net-mask>;<gateway-address>;'".format(value))

            return None

    def set_net_settings(self, netset: dict, adapter: str):
        """
        Run shell or batch script to change network settings with new parameters.

        :param netset:
        :return:
        """

        # check password
        if netset["password"] == self.password:
            path = os.path.join(os.path.dirname(__file__), self.change_settings_script_path)

            try:
                sp = subprocess.run([path, '--interface', adapter,
                                     '--ipv4', netset["ip-address"],
                                     '--dhcp', netset["dhcp_enabled"],
                                     '--subnet_mask', netset["net-mask"],
                                     '--gw', netset["gw-address"]])
                return sp.returncode
            except FileNotFoundError:
                # try pass path to the script as absolute path
                path = self.change_settings_script_path
                try:
                    sp = subprocess.run([path, '-a', adapter, '-i', netset["ip-address"], '-d', netset["dhcp_enabled"],
                                         '-n', netset["net-mask"], '-g', netset["gw-address"]])
                    return sp.returncode
                except FileNotFoundError:
                    logger.error("File of the networking setting script can't be found on path '{}'".format(path))
                    return RESULT_ERROR

        else:
            logger.error("Password for changing network settings is incorrect.")
            return RESULT_ERROR

        return RESULT_ERROR
        
    def get_adapter_by_uuid_st(self, uuid_st):

        uuid_name = uuid_st[5:]

        for name in self.interfaces.mac_addresses_dict:
            if self.interfaces.mac_addresses_dict[name]['uuid'] == uuid_name:
                return name

        return 'None'

