import pytest
import asyncio
import subprocess
import time

#@pytest.fixture
#def start_containers(scope="module"):
#    cmds = [
#        "docker build . -t bsdlib-test".split(),
#        "docker run -td --rm -p 2442:2442/udp -p 2442:2442/tcp -p 5668:5668/tcp -p 5667:5667/udp --name foobar123 bsdlib-test".split(),
#        "docker kill foobar123".split(),
#        "docker ps".split(),
#    ]
#    print(cmds[0])
#    subprocess.run(cmds[0])
#    print(cmds[1])
#    subprocess.run(cmds[1])
#    time.sleep(1)
#    yield
#    print(cmds[2])
#    subprocess.run(cmds[2])
#    print(cmds[3])
#    subprocess.run(cmds[3])


@pytest.fixture
def start_container():
    pass


async def udp_endpoint():
    reader, writer = await asyncio.open_connection("localhost", 5668)
    message = b"\0" * 10
    writer.write(message)
    await writer.drain()
    data = await reader.read(1024)
    assert data == b"none"
    writer.close()
    await writer.wait_closed()


def test_udp_endpoint(start_container):
    asyncio.run(udp_endpoint())


async def pong_tcp_endpoint():
    reader, writer = await asyncio.open_connection("localhost", 2442)
    message = b"foobar"
    print(f"Send: {message!r}")
    writer.write(message)
    await writer.drain()

    data = await reader.read(1024)
    assert data == b"PONG: foobar"
    writer.close()
    await writer.wait_closed()


def test_pong_tcp_endpoint(start_container):
    asyncio.run(pong_tcp_endpoint())


class EchoClientProtocol:
    def connection_made(self, transport):
        self.transport = transport
        self.transport.sendto(b"\0" * 10)


async def echo_client_protocol():
    loop = asyncio.get_running_loop()
    message = b"\0" * 10
    transport, protocol = await loop.create_datagram_endpoint(
        EchoClientProtocol, remote_addr=("localhost", 5667)
    )
    transport.close()


def test_echo_client_protocol(start_container):
    asyncio.run(echo_client_protocol())


async def dut_endpoint(msg):
    reader, writer = await asyncio.open_connection("localhost", 5668)
    message = msg
    print(f"Send: {message!r}")
    writer.write(message)
    await writer.drain()
    data = await reader.read(4096)
    writer.close()
    await writer.wait_closed()
    return data

def test_dut_proto():
    data = asyncio.run(dut_endpoint(b"asdf"))
    assert b"none" in data
    data = asyncio.run(dut_endpoint(b"foobar"))
    assert data
    asyncio.run(echo_client_protocol())
    data = asyncio.run(dut_endpoint(b"foobar"))
    assert b"\\x00\\x00\\x00" in data

