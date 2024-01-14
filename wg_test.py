import random
import timeit
from wg import *


def test_handshake_func():
    i_private, i_public = dh_generate()
    r_private, r_public = dh_generate()
    i_node, r_node = WgNode('', '', 0, i_private, i_public, []), WgNode('', '', 0, r_private, r_public, [])
    handshake = i_node.init_handshake(r_public)
    si_pub, timestamp, r_pair, resp_msg = r_node.respond_to_handshake(handshake.req)
    i_pair = handshake.on_response(resp_msg)
    assert r_pair.decrypt_data(i_pair.encrypt_data(b'h'*16)) == b'h'*16
    assert si_pub == i_public


def test_left_padding_int():
    l = random.randint(0, 2**64)
    left_padding_1 = b'\x00' * 4 + int.to_bytes(l, 8, 'little')
    left_padding_2 = (l << 32).to_bytes(12, 'little')
    assert left_padding_1 == left_padding_2


def test_bench_encrypt_decrypt():
    key1, key2 = os.urandom(32), os.urandom(32)
    send_keypair = WgTransportKeyPair(local_id=b'\x00'*4, peer_id=b'\x00'*4,
                                      send_key=key1, recv_key=key2, establish_time=time.time(), is_initiator=True)
    recv_keypair = WgTransportKeyPair(local_id=b'\x00'*4, peer_id=b'\x00'*4,
                                      send_key=key2, recv_key=key1, establish_time=time.time(), is_initiator=False)

    plain = b'h' * 1488
    loop_count = 100000
    elapsed = timeit.timeit('assert recv_keypair.decrypt_data(send_keypair.encrypt_data(plain)) == plain',
                            globals=locals(), number=loop_count)
    rate = (len(plain) * loop_count) / elapsed / 2**20
    print(f'encrypt/decrypt {loop_count} times takes {elapsed} seconds, {rate} MiB/s')
