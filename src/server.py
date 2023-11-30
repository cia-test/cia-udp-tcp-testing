import asyncio
import queue

PONG_PROTOCOL_PORT = 3000
UDP_SAMPLE_DUT_PORT = 3001
UDP_SAMPLE_TEST_PORT = 3002

data_q = asyncio.Queue()


class UdpPong(asyncio.DatagramProtocol):
    counter = 0

    def connection_made(self, transport):
        print("udp: pong connected")
        self.transport = transport

    def datagram_received(self, data, addr):
        print((self.counter, data))
        self.counter += 1
        self.transport.sendto(b"PONG: " + data, addr)


class UdpSampleTest(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        print("udp: UdpSampleTest ready")
        self.transport = transport

    def datagram_received(self, data, addr):
        print("udp: rx")
        if b"\x00\x00\x00" in data:
            asyncio.create_task(self.task_add(data))

    async def task_add(self, data):
        await data_q.put(data)


async def udp_sample_test_protocol(reader, writer):
    data = await reader.read(2048)
    print("tcp: sampletest")
    to_send = bytearray()
    if b"foobar" in data:
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
    writer.close()


async def tcp_pong(reader, writer):
    data = await reader.read(2048)
    print("tcp pong")
    a = b"PONG: " + data
    print(a.decode().strip())
    writer.write(a)
    await writer.drain()
    writer.close()


async def start_udp_tasks():
    loop = asyncio.get_running_loop()

    udpsample_dut = await loop.create_datagram_endpoint(
        UdpSampleTest, local_addr=("0.0.0.0", UDP_SAMPLE_DUT_PORT)
    )
    bsdlib_udp = await loop.create_datagram_endpoint(
        UdpPong, local_addr=("0.0.0.0", PONG_PROTOCOL_PORT)
    )


async def start_tcp_pong():
    udpsample_test = await asyncio.start_server(tcp_pong, "0.0.0.0", PONG_PROTOCOL_PORT)
    async with udpsample_test:
        await udpsample_test.serve_forever()


async def start_udpsample_test_protocol():
    udpsample_test = await asyncio.start_server(
        udp_sample_test_protocol, "0.0.0.0", UDP_SAMPLE_TEST_PORT
    )
    async with udpsample_test:
        await udpsample_test.serve_forever()


if __name__ == "__main__":
    asyncio.ensure_future(start_udp_tasks())
    asyncio.ensure_future(start_tcp_pong())
    asyncio.ensure_future(start_udpsample_test_protocol())
    asyncio.get_event_loop().run_forever()
