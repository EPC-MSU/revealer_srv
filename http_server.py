import os
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from http import HTTPStatus
from socketserver import ThreadingMixIn
import threading
from lib.ssdp import logger


class UPNPHTTPServerHandler(SimpleHTTPRequestHandler):

    """
    A HTTP handler that serves the UPnP XML files.
    """

    def __init__(self, *args, directory="webroot", **kwargs):

        if directory is None:
            directory = os.getcwd()
        self.directory = directory
        self.python36 = False
        try:
            super().__init__(*args, directory=directory, **kwargs)
        except TypeError:
            self.python36 = True
            # for compatibility with python 3.6
            try:
                super().__init__(*args, **kwargs)
            except ConnectionResetError:
                # try - except for windows requesting xml file while recalling network folder updating
                pass
        except ConnectionResetError:
            # try - except for windows requesting xml file while recalling network folder updating
            pass

    # override method for specific directory handler in python 3.6
    def translate_path(self, path):

        path = super().translate_path(path)
        if self.python36:
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
                # try to find interface name with this ip and its uuid for correct xml-data
                uuid_name = None
                # self.server.interfaces.update()
                uuid_name = self.server.interfaces.get_uuid_by_ip(ip_addr=self.request.getsockname()[0])
                if uuid_name is None:
                    self.server.interfaces.update()
                    uuid_name = self.server.interfaces.get_uuid_by_ip(ip_addr=self.request.getsockname()[0])

                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write(self.get_device_xml(text, uuid_name).encode())
                return
            except ConnectionResetError:
                return
            except FileNotFoundError:
                self.send_response(404)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                return

        if self.path == self.server.presentation_url:
            try:
                if self.server.redirect_port is None or self.server.redirect_port == "":
                    path = os.path.join(self.directory, self.server.presentation_url[1:])
                    if os.path.isdir(path):
                        for index in "index.html", "index.htm":
                            index = os.path.join(path, index)
                            if os.path.exists(index):
                                path = index
                                break
                    with open(path, "r") as f:
                        text = f.read()
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(text.encode())
                else:
                    ip_address = self.request.getsockname()[0]
                    self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                    self.send_header('Location',
                                     'http://' + ip_address + ':' + str(
                                         self.server.redirect_port) + self.server.presentation_url)
                    self.end_headers()
                return
            except ConnectionResetError:
                return
            except FileNotFoundError:
                print(f"File with path '{path}' not found.")
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

    def get_device_xml(self, text_file, device_uuid):
        """
        Get the main device descriptor xml file.
        """

        if device_uuid is None:
            device_uuid = "Undefined"

        return text_file.format(friendly_name=self.server.friendly_name,
                                manufacturer=self.server.manufacturer,
                                manufacturer_url=self.server.manufacturer_url,
                                model_description=self.server.model_description,
                                model_name=self.server.model_name,
                                model_number=self.server.model_number,
                                model_url=self.server.model_url,
                                serial_number=self.server.serial_number,
                                uuid=device_uuid,
                                presentation_url=self.server.presentation_url)


class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    # we don't allow to reuse HTTP-port since this behaviour is not cross-platform
    # on Windows: with allow_reuse_address = True
    #             one can create multiple server instances and only first one will be active
    # on Linux: with allow_reuse_address = True
    #           one can't create multiple server instances
    allow_reuse_address = False

    pass


class UPNPHTTPServerBase(ThreadingSimpleServer):
    """
    A simple HTTP server that knows the information about a UPnP device.
    """

    def __init__(self, server_address, request_handler_class):
        try:
            HTTPServer.__init__(self, server_address, request_handler_class)
        except OSError as e:
            logger.fatal("Error creating http server on port %d. "
                         "Please check that the port is not in use by other proccess or "
                         "wait for 1 minute before restarting the server since it may be"
                         " OS holding the socket from previous server instance. Error: %r"
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
        self.redirect_port = None
        self.interfaces = None


class UPNPHTTPServer(threading.Thread):
    """
    A thread that runs UPNPHTTPServerBase.
    """

    def __init__(self, port, friendly_name, manufacturer, manufacturer_url, model_description, model_name,
                 model_number, model_url, serial_number, uuid, presentation_url, interfaces, redirect_port=None):
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
        self.server.interfaces = interfaces

    def run(self):
        self.server.serve_forever()
