import base64
import hashlib
import json
import logging
import os
import queue
import selectors
import socket
import struct
import subprocess
import time
from collections import namedtuple
from ctypes import Structure, c_char, c_short
from fcntl import ioctl
from typing import Callable

from cryptography.exceptions import InvalidTag, InvalidSignature, InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hmac import HMAC

logger = logging.getLogger('wg')


def dh(private_key: bytes, public_key: bytes) -> bytes:
    private = X25519PrivateKey.from_private_bytes(private_key)
    public = X25519PublicKey.from_public_bytes(public_key)
    return private.exchange(public)


def dh_public(private_key: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()


def dh_generate() -> tuple[bytes, bytes]:
    private = X25519PrivateKey.generate()
    public = private.public_key()
    return private.private_bytes_raw(), public.public_bytes_raw()


def aead(key: bytes, counter: int, plain: bytes, auth: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key=key)
    nounce = b'\x00' * 4 + counter.to_bytes(8, 'little')
    return chacha.encrypt(nounce, data=plain, associated_data=auth)


def decrypt_aead(key: bytes, counter: int, encrypted: bytes, auth: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key=key)
    nounce = b'\x00' * 4 + counter.to_bytes(8, 'little')
    return chacha.decrypt(nounce, data=encrypted, associated_data=auth)


def hmac(key: bytes, input_: bytes) -> bytes:
    h = HMAC(key, hashes.BLAKE2s(32))
    h.update(input_)
    return h.finalize()


def mac(key: bytes, input_: bytes) -> bytes:
    h = hashlib.blake2s(key=key, digest_size=16)
    h.update(input_)
    return h.digest()


def hash(input_: bytes) -> bytes:
    h = hashes.Hash(hashes.BLAKE2s(32))
    h.update(input_)
    return h.finalize()


def kdf1(key: bytes, input_: bytes) -> bytes:
    t0 = hmac(key, input_)
    t1 = hmac(t0, b'\x01')
    return t1


def kdf2(key: bytes, input_: bytes) -> tuple[bytes, bytes]:
    t0 = hmac(key, input_)
    t1 = hmac(t0, b'\x01')
    t2 = hmac(t0, t1 + b'\x02')
    return t1, t2


def kdf3(key: bytes, input_: bytes) -> tuple[bytes, bytes, bytes]:
    t0 = hmac(key, input_)
    t1 = hmac(t0, b'\x01')
    t2 = hmac(t0, t1 + b'\x02')
    t3 = hmac(t0, t2 + b'\x03')
    return t1, t2, t3


CONSTRUCTION = 'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s'.encode()
IDENTIFIER = 'WireGuard v1 zx2c4 Jason@zx2c4.com'.encode()
LABEL_MAC1 = 'mac1----'.encode()
LABEL_COOKIE = 'cookie--'.encode()
REKEY_AFTER_MESSAGES = 2**60
REJECT_AFTER_MESSAGES = 2**64 - 2**13 - 1
REKEY_AFTER_TIME = 120
REJECT_AFTER_TIME = 180
REKEY_ATTEMPT_TIME = 90
REKEY_TIMEOUT = 5
KEEPALIVE_TIMEOUT = 10
MIN_HANDSHAKE_INTERVAL = 0.05   # 50ms


def tai64n(now: float) -> bytes:
    seconds = int(now)
    nanoseconds = int((now - seconds) * 1000000000)
    seconds = seconds + (2 ** 62) + 10  # last 10 are leap seconds
    return seconds.to_bytes(8, 'big') + nanoseconds.to_bytes(4, 'big')


# utility to serialize/deserialize wireguard messages(handshake init/handshake response/data)
# xx_format are for struct.pack/unpack
# HandshakeInit/HandshakeResponse/DataMessage are namedtuples for ease of message manipulating
handshake_init_prefix_format = '<I4s32s48s28s'
handshake_init_message_format = handshake_init_prefix_format + '16s16s'
HandshakeInit = namedtuple('HandShakeInit', 'type sender_index unencrypted_ephemeral encrypted_static encrypted_timestamp mac1 mac2')   # noqa
handshake_response_prefix_format = '<I4s4s32s16s'
handshake_response_message_format = handshake_response_prefix_format + '16s16s'
HandshakeResponse = namedtuple('HandShakeResponse', 'type sender_index receiver_index unencrypted_ephemeral encrypted_nothing mac1 mac2')   # noqa
data_message_header_format = '<I4s8s'
DataMessage = namedtuple('DataMessageHeader', 'type receiver_index counter encrypted')


class WgTransportKeyPair:
    key_pair_count = 0

    def __init__(self, local_id: bytes, peer_id: bytes, send_key: bytes,
                 recv_key: bytes, establish_time: float, is_initiator: bool):
        WgTransportKeyPair.key_pair_count += 1
        self.number = WgTransportKeyPair.key_pair_count
        self.local_id = local_id
        self.peer_id = peer_id
        self.send_cipher = ChaCha20Poly1305(send_key)
        self.recv_cipher = ChaCha20Poly1305(recv_key)
        self.establish_time = establish_time
        self.is_initiator = is_initiator
        self.send_count = 0
        self.max_recv_count = 0
        self.recv_window = 0  # 32-bitmap as a rolling window for received packets

    def __str__(self):
        return f'keypair {self.number}'

    def encrypt_data(self, data: bytes) -> DataMessage:
        remainder = len(data) % 16
        if remainder != 0:
            data += b'\x00' * (16 - remainder)
        count_bytes = self.send_count.to_bytes(8, 'little')
        nonce = (self.send_count << 32).to_bytes(12, 'little')
        encrypted = self.send_cipher.encrypt(nonce, data, b'')
        message = DataMessage(4, self.peer_id, count_bytes, encrypted)
        self.send_count += 1
        return message

    def decrypt_data(self, message: DataMessage) -> bytes | None:
        count = int.from_bytes(message.counter, 'little')
        # check if this packet is too old or has been received before, if so, discard it
        # this rolling window algorithm is borrowed from  page 57 of https://www.rfc-editor.org/rfc/rfc2401.txt
        diff = count - self.max_recv_count
        if diff >= 32:
            self.max_recv_count = count
            self.recv_window = 1
        elif diff > 0:
            self.max_recv_count = count
            # python int is unbounded, we have to keep it 32-bit wide
            self.recv_window = (self.recv_window << diff) & 0xffffffff
            self.recv_window |= 1   # set the bit for current count
        else:
            offset = -diff
            if diff >= 32:
                # this packet is too old, discard it
                return None
            mask = 1 << offset
            if self.recv_window & mask != 0:
                # this packet has been received before
                return None
            # mark this packet as received
            self.recv_window |= mask
        try:
            nonce = (count << 32).to_bytes(12, 'little')
            return self.recv_cipher.decrypt(nonce, message.encrypted, b'')
        except (InvalidKey, InvalidTag, InvalidSignature):
            return None


class WgHandshake:
    def __init__(self, req: HandshakeInit, on_response: Callable[[HandshakeResponse], WgTransportKeyPair]):
        self.start_time = time.time()
        self.req = req
        self.on_response = on_response


class WgPeer:
    def __init__(self, ip: str, endpoint: tuple[str, int], public: bytes, node: 'WgNode', psk: bytes):
        self.ip = ip
        self.endpoint = endpoint
        self.public = public
        self.node = node
        self.psk = psk
        self.prev_session: WgTransportKeyPair | None = None
        self.cur_session: WgTransportKeyPair | None = None
        self.handshake: WgHandshake | None = None
        self.last_received_handshake_init_tai64n = b'\x00' * 12
        self.send_queue = queue.Queue()
        self.last_addr = None
        self.last_received_time = None
        self.last_send_time = time.time()

    def send_data(self, data: bytes):
        self.expire_all_sessions_if_necessary()
        need_new_session = False
        cur = self.cur_session
        if not cur:
            logger.info('no valid session yet, start new session')
            need_new_session = True
        elif cur.send_count >= REJECT_AFTER_MESSAGES:
            logger.info('session expired for maximum messages, start new session')
            need_new_session = True
        elif cur.is_initiator and cur.establish_time + REKEY_AFTER_TIME < time.time():
            logger.info('session expired for rekey_after_time, start new session')
            need_new_session = True

        if need_new_session:
            self.send_queue.put(data)
            if self.handshake and time.time() < self.handshake.start_time + REKEY_ATTEMPT_TIME:
                return
            handshake = self.node.init_handshake(self)
            addr = self.last_addr or self.endpoint
            self.node.write_udp(handshake.req, addr)
            self.handshake = handshake
        else:
            data_msg = self.cur_session.encrypt_data(data)
            self.node.write_udp(data_msg, self.last_addr)
            self.last_send_time = time.time()

    def decrypt_data(self, message: DataMessage) -> bytes | None:
        self.expire_all_sessions_if_necessary()
        if not self.cur_session:
            return None
        if message.receiver_index == self.cur_session.local_id:
            session = self.cur_session
        elif self.prev_session and message.receiver_index == self.prev_session.local_id:
            session = self.prev_session
        else:
            return None
        return session.decrypt_data(message)

    def expire_all_sessions_if_necessary(self):
        if self.cur_session and self.cur_session.establish_time + REJECT_AFTER_TIME * 3 < time.time():
            self.prev_session, self.cur_session, self.handshake = None, None, None
            logger.info(f'all sessions expired')

    def set_cur_session(self, session: WgTransportKeyPair):
        self.prev_session, self.cur_session, self.handshake = self.cur_session, session, None
        logger.info(f'session rotated (prev, cur) = {self.prev_session}, {self.cur_session}')
        while not self.send_queue.empty():
            data = self.send_queue.get()
            self.node.write_udp(session.encrypt_data(data), self.last_addr)
            self.last_send_time = time.time()


# include/uapi/linux/if_tun.h
# define TUNSETIFF     _IOW('T', 202, int)
TUNSETIFF = 0x400454ca
TUNSETOWNER = TUNSETIFF + 2
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


class IfReq(Structure):
    _fields_ = [("name", c_char * 16), ("flags", c_short)]


class WgNode:
    def __init__(self, ip: str, listen_ip: str, listen_port: int, private: bytes, public: bytes, peers: list[WgPeer]):
        self.ip = ip
        self.listen_ip, self.listen_port = listen_ip, listen_port
        self.tun = None
        self.sock: socket.socket = None
        self.sock_write_queue: list[tuple[bytes, tuple[str, int]]] = []
        self.private = private
        self.public = public
        self.mac1_auth = hash(LABEL_MAC1 + self.public)
        self.peers = peers

    @classmethod
    def from_json(cls, json_file: str = 'wg.json') -> 'WgNode':
        with open(json_file) as f:
            conf = json.load(f)
            ip = conf['ip']
            listen_ip = conf.get('listen_ip', '0.0.0.0')
            listen_port = conf.get('listen_port', 0)
            private = base64.b64decode(conf['private'])
            public = dh_public(private)
            peers = []
            node = cls(ip, listen_ip, listen_port, private, public, peers)
            for peer in conf['peers']:
                peer_ip = peer['ip']
                peer_public = base64.b64decode(peer['public'])
                endpoint = peer.get('endpoint', '')
                if endpoint:
                    ip, port = endpoint.split(':')
                    peer_endpoint = (ip, int(port))
                else:
                    peer_endpoint = ('', 0)
                pre_shared_key = peer.get('pre_shared_key')
                if pre_shared_key:
                    psk = base64.b64decode(pre_shared_key)
                else:
                    psk = b'\x00' * 32
                peers.append(WgPeer(peer_ip, peer_endpoint, peer_public, node=node, psk=psk))
            return node

    def _setup_udp_sock(self):
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.listen_ip, self.listen_port))

    def _setup_tun_dev(self):
        """create a linux tun device and return it"""
        tun = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
        # struct.pack an instance of ifreq with setting ifrn_name
        req = IfReq(name='testun%d'.encode(), flags=IFF_TUN | IFF_NO_PI)
        ioctl(tun, TUNSETIFF, req)
        ioctl(tun, TUNSETOWNER, os.getuid())
        ifname = req.name.decode()
        subprocess.check_call(f'ip addr add {self.ip} dev {ifname}', shell=True)
        subprocess.check_call(f'ip link set dev {ifname} up ', shell=True)
        for peer in self.peers:
            subprocess.check_call(f'ip route add {peer.ip} via {self.ip}', shell=True)
        self.tun = tun

    def _setup_selector(self):
        os.set_blocking(self.tun, False)
        self.sock.setblocking(False)
        selector = selectors.DefaultSelector()
        selector.register(self.sock, selectors.EVENT_READ)
        selector.register(self.tun, selectors.EVENT_READ)
        return selector

    def serve(self):
        self._setup_udp_sock()
        self._setup_tun_dev()
        selector = self._setup_selector()
        last_check_alive_time = time.time()
        while True:
            events = selector.select(1)
            udp_ready = tun_ready = False
            for key, mask in events:
                if key.fd == self.tun:
                    tun_ready = True
                elif key.fd == self.sock.fileno():
                    udp_ready = True
            while tun_ready or udp_ready or self.sock_write_queue:
                if tun_ready:
                    try:
                        ip_packet = os.read(self.tun, 65535)
                    except BlockingIOError:
                        tun_ready = False
                    else:
                        self.on_tun_read(ip_packet)
                if udp_ready:
                    try:
                        data, addr = self.sock.recvfrom(65535)
                    except BlockingIOError:
                        udp_ready = False
                    else:
                        self.on_udp_read(data, addr)
                if self.sock_write_queue:
                    data, addr = self.sock_write_queue[0]
                    try:
                        self.sock.sendto(data, addr)
                        self.sock_write_queue.pop(0)
                    except BlockingIOError:
                        pass

            if time.time() - last_check_alive_time >= 1:
                last_check_alive_time = time.time()
                for peer in self.peers:
                    if peer.last_received_time is None:
                        continue
                    if time.time() - peer.last_send_time >= KEEPALIVE_TIMEOUT:
                        logger.info(f'sending keepalive to {peer.ip}')
                        peer.send_data(b'')

    def on_tun_read(self, ip_packet: bytes):
        """called when data read from tun(aka. ip packets to encapsulate in udp)"""
        # check if data is a valid ip packet
        if len(ip_packet) < 20:
            return
        # support ipv4 only for now
        version = ip_packet[0] >> 4
        if version != 4:
            return
        dst_addr = socket.inet_ntoa(ip_packet[16:20])
        if peer := self.get_peer(ip=dst_addr):
            peer.send_data(ip_packet)

    def on_udp_read(self, data: bytes, addr: tuple[str, int]):
        """called when data read from udp(aka. wireguard handshake messages or encrypted ip packets)"""
        if len(data) < 4:
            return
        msg_type = int.from_bytes(data[0:4], 'little', signed=False)
        if msg_type == 1:
            message = HandshakeInit._make(struct.unpack(handshake_init_message_format, data))
            if message.mac1 != mac(self.mac1_auth, data[:116]):
                logger.warning('invalid mac1 of handshake init from %s', addr)
                return
            try:
                self.respond_to_handshake(addr, message)
            except (InvalidKey, InvalidTag, InvalidSignature):
                logger.warning('invalid handshake init from %s', addr)
        elif msg_type == 2:
            message = HandshakeResponse._make(struct.unpack(handshake_response_message_format, data))
            if message.mac1 != mac(self.mac1_auth, data[:60]):
                logger.warning('invalid mac1 of handshake response from %s', addr)
                return
            if peer := self.get_peer(handshake_session_id=message.receiver_index):
                try:
                    keypair = peer.handshake.on_response(message)
                except (InvalidKey, InvalidTag, InvalidSignature, AssertionError):
                    logger.warning('invalid handshake response from %s', addr)
                    return
                peer.last_addr = addr
                peer.set_cur_session(keypair)
            else:
                logger.warning('handshake response from %s have no corresponding handshake init', addr)
        elif msg_type == 4:
            message_format = data_message_header_format + f'{len(data) - 16}s'
            message = DataMessage._make(struct.unpack(message_format, data))
            if peer := self.get_peer(session_id=message.receiver_index):
                if decrypted := peer.decrypt_data(message):
                    peer.last_addr = addr
                    peer.last_received_time = time.time()
                    os.write(self.tun, decrypted)

    def init_handshake(self, peer: WgPeer) -> WgHandshake:
        """called by initiator: initiate a wireguard handshake with responder's public key.

        :param peer: responder
        :return: (handshake init message to be read by responder, callback to process response from responder)
        """
        si_priv, si_pub, sr_pub = self.private, self.public, peer.public

        ck = hash(CONSTRUCTION)
        h = hash(ck + IDENTIFIER)
        h = hash(h + sr_pub)
        ei_priv, ei_pub = dh_generate()
        ck = kdf1(ck, ei_pub)
        h = hash(h + ei_pub)
        ck, k = kdf2(ck, dh(ei_priv, sr_pub))
        encrypted_static = aead(k, 0, si_pub, h)
        h = hash(h + encrypted_static)
        ck, k = kdf2(ck, dh(si_priv, sr_pub))
        encrypted_timestamp = aead(k, 0, tai64n(time.time()), h)
        h = hash(h + encrypted_timestamp)

        sender_index = os.urandom(4)
        mac1 = mac(hash(LABEL_MAC1 + sr_pub), struct.pack(handshake_init_prefix_format, 1, sender_index,
                                                          ei_pub, encrypted_static, encrypted_timestamp))
        mac2 = b'\x00' * 16

        def on_response(resp: HandshakeResponse) -> WgTransportKeyPair:
            """called by initiator: process handshake response from responder."""
            nonlocal ck, h
            er_pub = resp.unencrypted_ephemeral

            ck = kdf1(ck, er_pub)
            h = hash(h + er_pub)
            ck = kdf1(ck, dh(ei_priv, er_pub))
            ck = kdf1(ck, dh(si_priv, er_pub))
            ck, tao, key_nothing = kdf3(ck, peer.psk)
            h = hash(h + tao)
            nothing = decrypt_aead(key_nothing, 0, resp.encrypted_nothing, h)
            assert nothing == b''
            send_key, recv_key = kdf2(ck, b'')
            return WgTransportKeyPair(local_id=sender_index, peer_id=resp.sender_index,
                                      send_key=send_key, recv_key=recv_key, establish_time=time.time(),
                                      is_initiator=True)

        req = HandshakeInit(1, sender_index, ei_pub, encrypted_static, encrypted_timestamp, mac1, mac2)
        return WgHandshake(req, on_response)

    def respond_to_handshake(self, addr: tuple[str, int], msg: HandshakeInit):
        """called by responder: compose response message and generate keypair.

        :param addr: from which address is msg sent from
        :param msg: handshake init message
        """
        sr_priv, sr_pub = self.private, self.public

        ck = hash(CONSTRUCTION)
        h = hash(ck + IDENTIFIER)
        h = hash(h + sr_pub)
        er_priv, er_pub = dh_generate()
        ei_pub = msg.unencrypted_ephemeral
        ck = kdf1(ck, ei_pub)
        h = hash(h + ei_pub)
        ck, k = kdf2(ck, dh(sr_priv, ei_pub))
        si_pub = decrypt_aead(k, 0, msg.encrypted_static, h)
        peer = self.get_peer(peer_public=si_pub)

        if not peer:
            logger.warning('handshake init from %s have no corresponding peer', addr)
            return
        if peer.cur_session and time.time() - peer.cur_session.establish_time < MIN_HANDSHAKE_INTERVAL:
            logger.warning('handshake init from %s is too frequent', addr)
            return

        h = hash(h + msg.encrypted_static)
        ck, k = kdf2(ck, dh(sr_priv, si_pub))
        timestamp = decrypt_aead(k, 0, msg.encrypted_timestamp, h)
        if peer.last_received_handshake_init_tai64n >= timestamp:
            logger.warning('handshake init from %s is replayed', addr)
            return

        h = hash(h + msg.encrypted_timestamp)
        ck = kdf1(ck, er_pub)
        h = hash(h + er_pub)
        ck = kdf1(ck, dh(er_priv, ei_pub))
        ck = kdf1(ck, dh(er_priv, si_pub))
        ck, tao, k = kdf3(ck, peer.psk)
        h = hash(h + tao)
        encrypted_nothing = aead(k, 0, b'', h)
        recv_key, send_key = kdf2(ck, b'')

        encrypted_nothing = encrypted_nothing
        sender_index = os.urandom(4)
        receiver_index = msg.sender_index
        unencrypted_ephemeral = er_pub
        mac1 = mac(hash(LABEL_MAC1 + si_pub), struct.pack(handshake_response_prefix_format, 2, sender_index,
                                                          receiver_index, unencrypted_ephemeral, encrypted_nothing))
        mac2 = b'\x00' * 16
        keypair = WgTransportKeyPair(local_id=sender_index, peer_id=receiver_index,
                                     send_key=send_key, recv_key=recv_key,
                                     establish_time=time.time(), is_initiator=False)
        response = HandshakeResponse(2, sender_index, receiver_index, unencrypted_ephemeral,
                                     encrypted_nothing, mac1, mac2)
        self.write_udp(response, addr)
        peer.last_addr = addr
        peer.last_received_handshake_init_tai64n = timestamp
        peer.set_cur_session(keypair)

    def write_udp(self, message: HandshakeInit | HandshakeResponse | DataMessage, addr: tuple[str, int]):
        if isinstance(message, HandshakeInit):
            message_format = handshake_init_message_format
        elif isinstance(message, HandshakeResponse):
            message_format = handshake_response_message_format
        else:
            message_format = data_message_header_format + f'{len(message.encrypted)}s'
        data = struct.pack(message_format, *message)
        self.sock_write_queue.append((data, addr))

    def get_peer(self, ip: str | None = None, peer_public: bytes | None = None,
                 handshake_session_id: bytes | None = None, session_id: bytes | None = None) -> WgPeer | None:
        for peer in self.peers:
            if peer.ip == ip or peer.public == peer_public:
                return peer
            if session_id:
                if peer.cur_session and peer.cur_session.local_id == session_id:
                    return peer
                if peer.prev_session and peer.prev_session.local_id == session_id:
                    return peer
            if handshake_session_id:
                if peer.handshake and peer.handshake.req.sender_index == handshake_session_id:
                    return peer
        return None


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
    WgNode.from_json().serve()
