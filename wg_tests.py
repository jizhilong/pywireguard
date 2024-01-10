import unittest

from wg import *


class WgSessionTestCase(unittest.TestCase):
    def test_handshake_func(self):
        i_private, i_public = dh_generate()
        r_private, r_public = dh_generate()
        i_node, r_node = WgNode('', '', 0, i_private, i_public, []), WgNode('', '', 0, r_private, r_public, [])
        handshake = i_node.init_handshake(r_public)
        si_pub, timestamp, r_pair, resp_msg = r_node.respond_to_handshake(handshake.req)
        i_pair = handshake.on_response(resp_msg)
        assert r_pair.decrypt_data(i_pair.encrypt_data(b'h'*16)) == b'h'*16
        assert si_pub == i_public

    def test_encrypt_decrypt(self):
        key1, key2 = os.urandom(32), os.urandom(32)
        send_keypair = WgTransportKeyPair(local_id=b'\x00'*4, peer_id=b'\x00'*4,
                                          send_key=key1, recv_key=key2, establish_time=time.time(), is_initiator=True)
        recv_keypair = WgTransportKeyPair(local_id=b'\x00'*4, peer_id=b'\x00'*4,
                                          send_key=key2, recv_key=key1, establish_time=time.time(), is_initiator=False)

        loop_count = 100000
        start = time.time()
        msg = send_keypair.encrypt_data(b'h'*1480)
        for i in range(loop_count):
            msg = send_keypair.encrypt_data(b'h'*1480)
        elapsed = time.time() - start
        rate = (1480 * loop_count) / elapsed / 2**20
        print(f'encrypt {loop_count} times takes {elapsed} seconds, {rate} MiB/s')

        start = time.time()
        for i in range(loop_count):
            assert recv_keypair.decrypt_data(msg) is not None
        elapsed = time.time() - start
        rate = (1480 * loop_count) / elapsed / 2**20
        print(f'decrypt {loop_count} times takes {elapsed} seconds, {rate} MiB/s')
