import random
import threading
import timeit

import pytest as pytest
from scapy.layers.inet import raw, IP

from wg import *

psk = os.urandom(32)


@pytest.fixture
def wg_keys():
    return dh_generate(), dh_generate()


@pytest.fixture
def wg_ports():
    ports = []
    for i in range(2):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        ports.append(port)
        sock.close()
    return tuple(ports)


@pytest.fixture(autouse=True)
def mock_tun_setup(monkeypatch):
    def mock_setup_tun(self):
        pass
    monkeypatch.setattr(WgNode, '_setup_tun_dev', mock_setup_tun)


@pytest.fixture
def wg1(wg_keys, wg_ports):
    (private_1, public_1), (private_2, public_2) = wg_keys
    (port_1, port_2) = wg_ports
    node = WgNode(ip='10.0.0.1', listen_ip='127.0.0.1', listen_port=port_1,
                  private=private_1, public=public_1, peers=[])
    node.peers.append(WgPeer('10.0.0.2', ('127.0.0.1', port_2), public_2, node, psk))
    s1, s2 = socket.socketpair(type=socket.SOCK_DGRAM)
    node.tun = LinuxTunReaderWriter(s1.fileno())
    node._tun = s1   # prevent socket object from being garbage collected
    node.tunw= s2
    return node


@pytest.fixture
def wg2(wg_keys, wg_ports):
    (private_1, public_1), (private_2, public_2) = wg_keys
    (port_1, port_2) = wg_ports
    node = WgNode(ip='10.0.0.2', listen_ip='127.0.0.1', listen_port=port_2,
                  private=private_2, public=public_2, peers=[])
    node.peers.append(WgPeer('10.0.0.1', ('127.0.0.1', port_1), public_1, node, psk))
    s1, s2 = socket.socketpair(type=socket.SOCK_DGRAM)
    node.tun = LinuxTunReaderWriter(s1.fileno())
    node._tun = s1   # prevent socket object from being garbage collected
    node.tunw= s2
    return node


def test_integrate(wg1, wg2):
    threading.Thread(target=wg1.serve, daemon=True).start()
    threading.Thread(target=wg2.serve, daemon=True).start()

    def node1_to_node2(data: bytes):
        packet = IP(src=wg1.ip, dst=wg2.ip, len=len(data)) / data
        wg1.tunw.send(raw(packet))
        received_packet = IP(wg2.tunw.recv(65536))
        assert received_packet.dst == wg2.ip
        assert received_packet.len == len(data)
        assert raw(received_packet.payload)[:received_packet.len] == data

    def node2_to_node1(data: bytes):
        packet = IP(src=wg2.ip, dst=wg1.ip, len=len(data)) / data
        wg2.tunw.send(raw(packet))
        received_packet = IP(wg1.tunw.recv(65536))
        assert received_packet.dst == wg1.ip
        assert received_packet.len == len(data)
        assert raw(received_packet.payload)[:received_packet.len] == data

    node1_to_node2(b'hello')
    node2_to_node1(b'world')
    assert wg1.peers[0].cur_session.send_count == 1
    assert wg2.peers[0].cur_session.send_count == 1
    assert wg1.peers[0].cur_session.max_recv_count == 0
    assert wg2.peers[0].cur_session.max_recv_count == 0
    assert wg1.peers[0].cur_session.recv_window == 1
    assert wg2.peers[0].cur_session.recv_window == 1


def test_left_padding_int():
    rand_int = random.randint(0, 2**64)
    left_padding_1 = b'\x00' * 4 + int.to_bytes(rand_int, 8, 'little')
    left_padding_2 = (rand_int << 32).to_bytes(12, 'little')
    assert left_padding_1 == left_padding_2


def test_bench_encrypt_decrypt():
    key1, key2 = os.urandom(32), os.urandom(32)
    send_keypair = WgTransportKeyPair(local_id=b'\x00'*4, peer_id=b'\x00'*4,
                                      send_key=key1, recv_key=key2, establish_time=time.time(), is_initiator=True)
    recv_keypair = WgTransportKeyPair(local_id=b'\x00'*4, peer_id=b'\x00'*4,
                                      send_key=key2, recv_key=key1, establish_time=time.time(), is_initiator=False)

    plain = b'h' * 1488
    loop_count = 10000
    elapsed = timeit.timeit('assert recv_keypair.decrypt_data(send_keypair.encrypt_data(plain)) == plain',
                            globals=locals(), number=loop_count)
    rate = (len(plain) * loop_count) / elapsed / 2**20
    print(f'encrypt/decrypt {loop_count} times takes {elapsed} seconds, {rate} MiB/s')


def test_data_replay_check():
    key1, key2 = os.urandom(32), os.urandom(32)
    send_keypair = WgTransportKeyPair(local_id=b'\x00'*4, peer_id=b'\x00'*4,
                                      send_key=key1, recv_key=key2, establish_time=time.time(), is_initiator=True)
    recv_keypair = WgTransportKeyPair(local_id=b'\x00'*4, peer_id=b'\x00'*4,
                                      send_key=key2, recv_key=key1, establish_time=time.time(), is_initiator=False)

    plain = b'h' * 1488
    encrypted = [send_keypair.encrypt_data(plain) for i in range(32)]
    random.shuffle(encrypted)
    for msg in encrypted:
        assert recv_keypair.decrypt_data(msg) == plain
    for msg in encrypted:
        assert recv_keypair.decrypt_data(msg) is None
