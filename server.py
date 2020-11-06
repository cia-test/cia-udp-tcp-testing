import asyncio
import ssl

BSDLIB_PORT = 2442
BSDLIB_PORT_SSL = 2443
UDP_SAMPLE_DUT_PORT = 5667
UDP_SAMPLE_TEST_PORT = 5668

counter = 0
data_q = asyncio.Queue()
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain(certfile='server.crt', keyfile='server.key')

class BSDLibTestProtocol(asyncio.DatagramProtocol):
    counter = 0
    def __init__(self):
        super().__init__()
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, data, addr):
        print((self.counter, data))
        self.counter += 1
        self.transport.sendto(b'PONG: '+data, addr)

async def bsdlib_test_protocol_tls(reader, writer):
    global counter
    data = await reader.read(2048)
    print((counter, data))
    counter += 1
    writer.write(bytes("PONG: {}".format(data).encode()))
    await writer.drain()
    writer.close()

class UDPSampleDUTProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        print("dut rx")
        if b'\x00\x00\x00' in data:
            loop = asyncio.get_event_loop()
            loop.create_task(self.task_add(data))

    async def task_add(self, data):
        await data_q.put(data)

async def udp_sample_test_protocol(reader, writer):
    data = await reader.read(2048)
    print("tcp")
    to_send = bytearray()
    if b'foobar' in data:
        while True:
            try:
                to_send.extend(f"Data: {data_q.get_nowait()}\n".encode())
            except asyncio.QueueEmpty:
                break
    if not to_send:
        writer.write(b"none")
    else:
        writer.write(to_send)       
    await writer.drain()
    print("done")

def start_server():
    loop = asyncio.get_event_loop()
    bsdlib_ipv4_udp = loop.create_datagram_endpoint(BSDLibTestProtocol,local_addr=('0.0.0.0',BSDLIB_PORT))
    bsdlib_ipv6_udp = loop.create_datagram_endpoint(BSDLibTestProtocol,local_addr=('::',BSDLIB_PORT))
    bsdlib_ipv4_tcp = asyncio.start_server(bsdlib_test_protocol_tls, '0.0.0.0', BSDLIB_PORT, loop=loop)
    bsdlib_ipv6_tcp = asyncio.start_server(bsdlib_test_protocol_tls, '::', BSDLIB_PORT, loop=loop)
    bsdlib_ipv4_tcp_ssl = asyncio.start_server(bsdlib_test_protocol_tls, '0.0.0.0', BSDLIB_PORT_SSL, loop=loop, ssl=ssl_context)
    bsdlib_ipv6_tcp_ssl = asyncio.start_server(bsdlib_test_protocol_tls, '::', BSDLIB_PORT_SSL, loop=loop, ssl=ssl_context)
    udpsample_dut = loop.create_datagram_endpoint(UDPSampleDUTProtocol,local_addr=('0.0.0.0',UDP_SAMPLE_DUT_PORT))
    udpsample_test = asyncio.start_server(udp_sample_test_protocol, '0.0.0.0', UDP_SAMPLE_TEST_PORT, loop=loop)
    
    loop.run_until_complete(bsdlib_ipv4_tcp)
    loop.run_until_complete(bsdlib_ipv4_udp)
    loop.run_until_complete(bsdlib_ipv6_tcp)
    loop.run_until_complete(bsdlib_ipv6_udp)
    loop.run_until_complete(bsdlib_ipv4_tcp_ssl)
    loop.run_until_complete(bsdlib_ipv6_tcp_ssl)
    loop.run_until_complete(udpsample_dut)
    loop.run_until_complete(udpsample_test)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    start_server()


