from asyncio import get_event_loop, _async as ensure_future
import logging


class _RevealerProtocol:
    # Class, with can handle request and return response to revealer
    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        response_port = int(data.decode("ascii").split(" ")[1])
        logging.info("REQUEST: %s, PORT: %d" %
                     (data.decode("ascii").split(" ")[0], response_port))
        self.transport.sendto(
            "DISCOVER_CUBIELORD_RESPONSE 00-00-00-00-00-00".encode(),
            (addr[0], response_port)
        )


class RevealerServer:
    # Class-server, with wait request from revealer
    def __init__(self, loop=None):
        self._loop = loop or get_event_loop()

        self._server = None

        async def start():
            self._server = await self._loop.create_datagram_endpoint(
                _RevealerProtocol,
                local_addr=("0.0.0.0", 8008)
            )

        # Invoke start when event loop is started
        self._loop.call_soon(ensure_future, start())


if __name__ == "__main__":
    logging.basicConfig(format="%(levelname)s\t%(module)s:\t%(message)s",
                        level=logging.INFO)
    ioloop = get_event_loop()
    server = RevealerServer(loop=ioloop)
    ioloop.run_forever()
