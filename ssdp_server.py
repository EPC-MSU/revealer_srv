from lib.ssdp import SSDPServer, logger
import socket
import random
from platform import system
from email.utils import formatdate
import ifaddr
from errno import ENOPROTOOPT
import sys
import ipaddress

SSDP_PORT = 1900
SSDP_ADDR = '239.255.255.250'
bad_interfaces = []

RESULT_OK = 0
RESULT_ERROR = 1


class UPNPSSDPServer(SSDPServer):
    def __init__(self):
        SSDPServer.__init__(self)
        self.adapters = ifaddr.get_adapters()

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
                if ip.ip == "127.0.0.1":
                    continue
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
        logger.debug('Discovery request for %s' % headers['st'])

        # Do we know about this service?
        for i in self.known.values():
            if i['MANIFESTATION'] == 'remote':
                continue
            if headers['st'] == 'ssdp:all' and i['SILENT']:
                continue
            if i['ST'] == headers['st'] or headers['st'] == 'ssdp:all':

                print()
                print()
                logger.info('Discovery request from (%s,%d) for %s' % (host, port, headers['st']))

                response = ['HTTP/1.1 200 OK']

                usn = None
                for k, v in i.items():
                    if k == 'USN':
                        usn = v
                    if k == 'LOCATION':
                        v = self._create_location_link(host_ip=host)

                    if k not in ('MANIFESTATION', 'SILENT', 'HOST'):
                        response.append('%s: %s' % (k, v))

                if usn:
                    response.append('DATE: %s' % formatdate(timeval=None, localtime=False, usegmt=True))

                    response.extend(('', ''))
                    delay = random.randint(0, int(headers['mx']))

                    self.send_it('\r\n'.join(response), (host, port), delay, usn)

                    # NOTIFY - to make sure the response reaches Revealer
                    self.notify_from_all_interfaces(usn)

    def notify_from_all_interfaces(self, usn):
        self.adapters = ifaddr.get_adapters()
        for adapter in self.adapters:
            for ip in adapter.ips:
                if not isinstance(ip.ip, str):
                    continue
                if ip.ip == '127.0.0.1':
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
        resp.extend(('', ''))
        logger.debug('do_notify content', resp)
        try:
            self.sock.sendto('\r\n'.join(resp).encode(), (SSDP_ADDR, SSDP_PORT))
            self.sock.sendto('\r\n'.join(resp).encode(), (SSDP_ADDR, SSDP_PORT))
        except (AttributeError, socket.error) as msg:
            logger.warning("failure sending out NOTIFY response: %r" % msg)
