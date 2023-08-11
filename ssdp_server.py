from lib.ssdp import SSDPServer, logger
import socket
import random
from email.utils import formatdate
import ifaddr
from errno import ENOPROTOOPT
import sys


SSDP_PORT = 1900
SSDP_ADDR = '239.255.255.250'
adapters = ifaddr.get_adapters()
bad_interfaces = []


class UPNPSSDPServer(SSDPServer):
    def __init__(self):
        SSDPServer.__init__(self)

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except socket.error as le:
                # RHEL6 defines SO_REUSEPORT but it doesn't work
                if le.errno == ENOPROTOOPT:
                    pass
                else:
                    raise

        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)

        ssdp_addr = socket.inet_aton(SSDP_ADDR)

        # Joining multicast on all adapters
        for adapter in adapters:
            for ip in adapter.ips:
                if not isinstance(ip.ip, str):
                    continue
                if ip.ip == '127.0.0.1':
                    continue

                interface = socket.inet_aton(ip.ip)
                try:
                    self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, ssdp_addr + interface)
                    logger.info('Joined multicast on interface %s/%d' % (ip.ip, ip.network_prefix))
                except socket.error as msg:
                    logger.warn("Failed to join multicast on interface %s. This interface will be ignored. %r"
                                % (ip.ip, msg))
                    bad_interfaces.append(ip.ip)
                    continue

        try:
            self.sock.bind(('', SSDP_PORT))
        except (OSError) as e:
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

    def discovery_request(self, headers, host_port):

        (host, port) = host_port

        logger.info('Discovery request from (%s,%d) for %s' % (host, port, headers['st']))
        logger.info('Discovery request for %s' % headers['st'])

        # Do we know about this service?
        for i in self.known.values():
            if i['MANIFESTATION'] == 'remote':
                continue
            if headers['st'] == 'ssdp:all' and i['SILENT']:
                continue
            if i['ST'] == headers['st'] or headers['st'] == 'ssdp:all':
                response = ['HTTP/1.1 200 OK']

                for k, v in i.items():
                    if k == 'USN':
                        usn = v
                    if k == 'LOCATION':
                        v = '/Basic_info.xml'
                    if k not in ('MANIFESTATION', 'SILENT', 'HOST'):
                        response.append('%s: %s' % (k, v))

                if usn:
                    response.append('DATE: %s' % formatdate(timeval=None, localtime=False, usegmt=True))

                    response.extend(('', ''))
                    delay = random.randint(0, int(headers['mx']))

                    self.send_it('\r\n'.join(response), (host, port), delay, usn)

                    # NOTIFY - to make sure the response reaches Revealer
                    logger.info('Notifying host (%s,%d)' % (host, port))

                    for adapter in adapters:
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
                                logger.warn("failure connecting to interface %s: %r" % (ip.ip, msg))
                                continue

                            # format: LOCATION: http://172.16.130.67:80/Basic_info.xml
                            url = 'http://{}:80/Basic_info.xml'.format(ip.ip)
                            self.known[usn]['LOCATION'] = url

                            self.do_notify(usn)
