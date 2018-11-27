import asyncio
import ssl

PORT = 2442
PORT_SSL = 2443

counter = 0

ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain(certfile='server.crt', keyfile='server.key')

class DiscoveryProtocol(asyncio.DatagramProtocol):
    counter = 0
    def __init__(self):
        super().__init__()
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, data, addr):
        print((self.counter, data))
        self.counter += 1
        self.transport.sendto(b'PONG: '+data, addr)

counter = 0
async def handle_echo(reader, writer):
    global counter
    data = await reader.read(2048)
    print((counter, data))
    counter += 1
    writer.write(bytes("PONG: {}".format(data).encode()))
    await writer.drain()
    writer.close()


def start_server():
    loop = asyncio.get_event_loop()
    ipv4_udp = loop.create_datagram_endpoint(DiscoveryProtocol,local_addr=('0.0.0.0',PORT))
    ipv6_udp = loop.create_datagram_endpoint(DiscoveryProtocol,local_addr=('::',PORT))
    ipv4_tcp = asyncio.start_server(handle_echo, '0.0.0.0', PORT, loop=loop)
    ipv6_tcp = asyncio.start_server(handle_echo, '::', PORT, loop=loop)
    ipv4_tcp_ssl = asyncio.start_server(handle_echo, '0.0.0.0', PORT_SSL, loop=loop, ssl=ssl_context)
    ipv6_tcp_ssl = asyncio.start_server(handle_echo, '::', PORT_SSL, loop=loop, ssl=ssl_context)
    loop.run_until_complete(ipv4_tcp)
    loop.run_until_complete(ipv4_udp)
    loop.run_until_complete(ipv6_tcp)
    loop.run_until_complete(ipv6_udp)
    loop.run_until_complete(ipv4_tcp_ssl)
    loop.run_until_complete(ipv6_tcp_ssl)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    start_server()


