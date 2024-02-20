import os

from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
import threading
from lib.ssdp import logger
import sys


class UPNPHTTPServerHandler(SimpleHTTPRequestHandler):
    """
    A HTTP handler that serves the UPnP XML files.
    """

    def __init__(self, *args, directory="webroot", **kwargs):

        if directory is None:
            directory = os.getcwd()
        self.directory = directory
        try:
            super().__init__(*args, directory=directory, **kwargs)
        except TypeError:
            # for compatibility with python 3.6
            super().__init__(*args, **kwargs)
        except ConnectionResetError:
            # try - except for windows requesting xml file while recalling network folder updating
            pass

    # override method for specific directory handler in python 3.6
    def translate_path(self, path):
        path = super().translate_path(path)
        cur_path = os.getcwd()

        add_path = path[len(cur_path):]
        path = os.path.join(cur_path, self.directory) + add_path

        return path

    # Handler for the GET requests
    # We override this method to be able to modify xml file
    def do_GET(self):
        if self.path == '/Basic_info.xml':
            try:
                path = os.path.join(self.directory, 'Basic_info.xml')
                with open(path, "r") as f:
                    text = f.read()
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write(self.get_device_xml(text).encode())
                return
            except ConnectionResetError:
                return
            except FileNotFoundError:
                self.send_response(404)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                return

        """Serve a GET request."""
        f = self.send_head()
        if f:
            try:
                self.copyfile(f, self.wfile)
            finally:
                f.close()

    def get_device_xml(self, text_file):
        """
        Get the main device descriptor xml file.
        """

        return text_file.format(friendly_name=self.server.friendly_name,
                                manufacturer=self.server.manufacturer,
                                manufacturer_url=self.server.manufacturer_url,
                                model_description=self.server.model_description,
                                model_name=self.server.model_name,
                                model_number=self.server.model_number,
                                model_url=self.server.model_url,
                                serial_number=self.server.serial_number,
                                uuid=self.server.uuid,
                                presentation_url=self.server.presentation_url)


class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass


class UPNPHTTPServerBase(ThreadingSimpleServer):
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


class UPNPHTTPServer(threading.Thread):
    """
    A thread that runs UPNPHTTPServerBase.
    """

    def __init__(self, port, friendly_name, manufacturer, manufacturer_url, model_description, model_name,
                 model_number, model_url, serial_number, uuid, presentation_url):
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

    def run(self):
        self.server.serve_forever()
