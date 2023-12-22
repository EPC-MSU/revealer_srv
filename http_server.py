from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from lib.ssdp import logger
import sys


html_page_index = """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Revealer Server</title>
  </head>
  <body>
    <h1>Revealer Server</h1>
    <p>This is default device web page provided by Revealer Server – UPnP SSDP discovery server.</p>
    <p>In case you have alternative implementation of the device web page
    set correct URL in the discovery server configuration file.</p>
  </body>
</html>
"""

html_page_404 = """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>404 - Page not found</title>
  </head>
  <body>
    <h1>404 - Page not found</h1>
    <p>This page provided by Revealer Server – UPnP SSDP discovery server.</p>
  </body>
</html>
"""


class UPNPHTTPServerHandler(BaseHTTPRequestHandler):
    """
    A HTTP handler that serves the UPnP XML files.
    """

    # Handler for the GET requests
    def do_GET(self):

        if self.path == '/Basic_info.xml':
            self.send_response(200)
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(self.get_device_xml().encode())
            return
        if self.path == '/index.html':
            """print(self.request.getsockname()[0])
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html_page_index.encode())"""

            if self.server.redirect_port is None:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html_page_index.encode())
            else:
                ip_address = self.request.getsockname()[0]
                self.send_response(302)
                self.send_header('Location','http://' + ip_address + ':' + str(self.server.redirect_port) + '/index.html')
                self.end_headers()
            return
        if self.path == '/redirect.html':
            ip_address = self.request.getsockname()[0]
            self.send_response(301)
            self.send_header('Location','https://' + ip_address + ':8888/tree')
            self.end_headers()
            return
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html_page_404.encode())
            return

    def get_device_xml(self):
        """
        Get the main device descriptor xml file.
        """
        xml = """<root>
    <specVersion>
        <major>1</major>
        <minor>0</minor>
    </specVersion>
    <device>
        <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
        <friendlyName>{friendly_name}</friendlyName>
        <manufacturer>{manufacturer}</manufacturer>
        <manufacturerURL>{manufacturer_url}</manufacturerURL>
        <modelDescription>{model_description}</modelDescription>
        <modelName>{model_name}</modelName>
        <modelNumber>{model_number}</modelNumber>
        <modelURL>{model_url}</modelURL>
        <serialNumber>{serial_number}</serialNumber>
        <UDN>uuid:{uuid}</UDN>
        <presentationURL>{presentation_url}</presentationURL>
    </device>
</root>"""
        return xml.format(friendly_name=self.server.friendly_name,
                          manufacturer=self.server.manufacturer,
                          manufacturer_url=self.server.manufacturer_url,
                          model_description=self.server.model_description,
                          model_name=self.server.model_name,
                          model_number=self.server.model_number,
                          model_url=self.server.model_url,
                          serial_number=self.server.serial_number,
                          uuid=self.server.uuid,
                          presentation_url=self.server.presentation_url)


class UPNPHTTPServerBase(HTTPServer):
    """
    A simple HTTP server that knows the information about a UPnP device.
    """
    def __init__(self, server_address, request_handler_class):
        try:
            HTTPServer.__init__(self, server_address, request_handler_class)
        except OSError as e:
            logger.fatal("Error creating http server on port %d. Please check that the port is not in use: %r"
                         % (server_address[1], e))
            sys.exit()
        self.port = None
        self.friendly_name = None
        self.manufacturer = None
        self.manufacturer_url = None
        self.model_description = None
        self.model_name = None
        self.model_url = None
        self.serial_number = None
        self.uuid = None
        self.presentation_url = None
        self.redirect_port = None  # port from the configuration to which we should redirect index.html if it is defined


class UPNPHTTPServer(threading.Thread):
    """
    A thread that runs UPNPHTTPServerBase.
    """

    def __init__(self, port, friendly_name, manufacturer, manufacturer_url, model_description, model_name,
                 model_number, model_url, serial_number, uuid, presentation_url, redirect_port=None):
        threading.Thread.__init__(self, daemon=True)
        self.server = UPNPHTTPServerBase(('0.0.0.0', port), UPNPHTTPServerHandler)
        self.server.port = port
        self.server.friendly_name = friendly_name
        self.server.manufacturer = manufacturer
        self.server.manufacturer_url = manufacturer_url
        self.server.model_description = model_description
        self.server.model_name = model_name
        self.server.model_number = model_number
        self.server.model_url = model_url
        self.server.serial_number = serial_number
        self.server.uuid = uuid
        self.server.presentation_url = presentation_url
        self.server.redirect_port = redirect_port

    def run(self):
        self.server.serve_forever()
