import asyncio
import socket
import threading
import ssl
import queue

BSDLIB_PORT = 3000
UDP_SAMPLE_DUT_PORT = 3001
UDP_SAMPLE_TEST_PORT = 3002

counter = 0
data_q = asyncio.Queue()


class UdpPong(asyncio.DatagramProtocol):
    counter = 0

    def connection_made(self, transport):
        print("udp_pong connected")
        self.transport = transport

    def datagram_received(self, data, addr):
        print((self.counter, data))
        self.counter += 1
        self.transport.sendto(b"PONG: " + data, addr)


class UdpSampleTest(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        print("UDPSampleDUTProtocol connected")
        self.transport = transport

    def datagram_received(self, data, addr):
        print("dut rx")
        if b"\x00\x00\x00" in data:
            asyncio.create_task(self.task_add(data))

    async def task_add(self, data):
        await data_q.put(data)


async def udp_sample_test_protocol(reader, writer):
    data = await reader.read(2048)
    print("tcp")
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


def tcp_pong():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print("started")
        s.bind(("0.0.0.0", BSDLIB_PORT))
        s.listen()
        print("accept")
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                data = conn.recv(1024)
                if not data:
                    continue
                try:
                    resp = f"PONG: {data.decode()}"
                except UnicodeDecodeError:
                    resp = "Error unable to decode"
                conn.sendall(resp.encode())


def tcp_udp_sample():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print("started")
        s.bind(("0.0.0.0", UDP_SAMPLE_TEST_PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                data = conn.recv(1024)
                if not "foobar" in data:
                    conn.sendall(b"none")
                    continue
                resp = bytearray()
                while True:
                    try:
                        resp.extend(f"Data: {data_q.get_nowait()}\n".encode())
                    except queue.Empty:
                        break
                if resp:
                    conn.sendall(resp)
                else:
                    conn.sendall(b"none")


async def start_server():
    loop = asyncio.get_running_loop()
    udpsample_dut = await loop.create_datagram_endpoint(
        UdpSampleTest, local_addr=("0.0.0.0", UDP_SAMPLE_DUT_PORT)
    )
    bsdlib_udp = await loop.create_datagram_endpoint(
        UdpPong, local_addr=("0.0.0.0", BSDLIB_PORT)
    )
    udpsample_test = await asyncio.start_server(
        udp_sample_test_protocol, "0.0.0.0", UDP_SAMPLE_TEST_PORT, family=socket.AF_INET
    )
    async with udpsample_test:  # , udpsample_test:
        await udpsample_test.serve_forever()  # , udpsample_test.serve_forever()


if __name__ == "__main__":
    a = threading.Thread(target=tcp_pong)
    a.start()
    # a = threading.Thread(target=tcp_udp_sample)
    # a.start()
    asyncio.run(start_server())
