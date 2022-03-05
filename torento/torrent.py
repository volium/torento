import time
import struct
import bcoding
import hashlib
import requests
import socket
import random
from urllib.parse import urlparse

class TorrentFile():

    def __init__(self):
        self._name = None
        self._length = None
        self._md5sum = None


class TorrentMultiFile(TorrentFile):

    def __init__(self):
        super().__init__()
        self._path = None


class Torrent():

    def __init__(self):

        self._torrent = None
        self._info = {}
        self._tracker = {}
        self._piece_length = None
        self._pieces = None
        self._total_length = 0
        self._files = []

    @property
    def torrent(self):
        return self._torrent

    @property
    def info(self):
        return self._info

    @property
    def tracker(self):
        return self._tracker

    @property
    def piece_length(self):
        return self._piece_length

    @property
    def pieces(self):
        return self._pieces

    @property
    def total_length(self):
        return self._total_length

    @property
    def files(self):
        return self._files


    def load_torrent(self, torrent_file=None):
        with open(torrent_file, 'rb') as fh:
            self._torrent = bcoding.bdecode(fh.read())
            self._piece_length = self._torrent["info"]["piece length"]
            self._peces = self._torrent["info"]["pieces"]
            self._tracker = self._torrent["announce"]
            self._info_hash = hashlib.sha1(bcoding.bencode(self._torrent["info"])).digest()
            self._peer_id = self.generate_peer_id()
            self.init_files()

    def generate_peer_id(self):
        seed = str(time.time())
        return hashlib.sha1(seed.encode('utf-8')).digest()

    def init_files(self):
        root = self._torrent["info"]["name"]

        if "files" in self._torrent["info"]:
            for file_in_torrent in self._torrent["info"]["files"]:
                file_path = file_in_torrent["path"]
                file_size = file_in_torrent["length"]
                self._files.append((*file_path, file_size))
                self._total_length += file_size


class UdpTrackerConnection():

    _CONNECTION_ID = 0x41727101980

    def __init__(self):
        # connection_id (int64_t) - Initialized to 0x41727101980
        self.connection_id = self._CONNECTION_ID
        # action (int32_t) - 0 for a connection request
        self.action = 0
        # action (int32_t) - 0 for a connection request
        self.transaction_id = random.randint(0, 0xFFFFFFF)

    def serialize(self):
        buffer = b""
        buffer += struct.pack("!q", self.connection_id)
        buffer += struct.pack("!i", self.action)
        buffer += struct.pack("!i", self.transaction_id)
        return buffer

    def deserialize(self, buffer):
        self.action = struct.unpack("!i", buffer[:4])[0]
        self.transaction_id = struct.unpack("!i", buffer[4:8])[0]
        self.connection_id = struct.unpack("!q", buffer[8:])[0]
        self.connection_id = struct.unpack("!q", buffer[8:])[0]

    def __str__(self):
        return f"action: {self.action}\n" + \
               f"connection id: {self.connection_id}\n" + \
               f"transaction id: {self.transaction_id}\n"

class PeerHandshake():

    def __init__(self, info_hash, peer_id):

        # NOTE: In version 1.0 of the BitTorrent protocol, pstrlen = 19, and pstr = "BitTorrent protocol".
        HANDSHAKE_PSTR = b"BitTorrent protocol"
        HANDSHAKE_PSTR_LEN = len(HANDSHAKE_PSTR)
        # int8_t pstrlen String length of <pstr>, as a single raw byte.
        self.pstrlen = HANDSHAKE_PSTR_LEN & 0xFF
        # variable length String identifier of the protocol
        self.pstr = HANDSHAKE_PSTR
        # int8_t[8] reserved Eight (8) reserved bytes (64 bits). All current implementations use all zeroes
        self.reserved = 0
        # int8_t[20] info_hash: 20-byte SHA1 hash of the info key in the metainfo file. This is the same info_hash that is transmitted in tracker requests.
        self.info_hash = info_hash
        # int8_t[20] peer_id: 20-byte string used as a unique ID for the client. This is usually the same peer_id that is transmitted in tracker requests (but not always e.g. an anonymity option in Azureus).
        self.peer_id = peer_id

    def serialize(self):
        buffer = b""
        buffer += struct.pack("!B", self.pstrlen)
        buffer += struct.pack("!s", self.pstr)
        buffer += struct.pack("!q", self.reserved)
        buffer += self.info_hash  # already byte enconded
        buffer += self.peer_id  # already byte enconded
        return buffer

    def deserialize(self, buffer):

        pstrlen = struct.unpack("!c", buffer[:1])[0]
        pstr = struct.unpack("!s", buffer[1:pstrlen])[0]
        reserved = struct.unpack("!i", buffer[pstrlen:pstrlen+8])[0]
        info_hash = struct.unpack("!i", buffer[pstrlen+8:pstrlen+8+20])[0]
        peer_id = struct.unpack("!i", buffer[pstrlen+8+20:pstrlen+8+20+20])[0]

    def __str__(self):
        return f"pstrlen: {self.pstrlen}\n" + \
               f"pstr: {self.pstr}\n" + \
               f"reserved: {self.reserved}\n" + \
               f"info_hash: {self.info_hash}\n" + \
               f"peer_id: {self.peer_id}\n"

class UdpTrackerAnnouncement():

    def __init__(self, connection_id, info_hash, peer_id):
        # int64_t connection_id The connection id acquired from establishing the connection.
        self.connection_id = connection_id
        # int32_t action Action. in this case, 1 for announce. See actions.
        self.action = 1
        # int32_t transaction_id Randomized by client.
        self.transaction_id = random.randint(0, 0xFFFFFFF)
        # int8_t[20] info_hash The info-hash of the torrent you want announce yourself in.
        self.info_hash = info_hash
        # int8_t[20] peer_id Your peer id.
        self.peer_id = peer_id
        # int64_t downloaded The number of byte you've downloaded in this session.
        self.downloaded = 0
        # int64_t left The number of bytes you have left to download until you're finished.
        self.left = 0
        # int64_t uploaded The number of bytes you have uploaded in this session.
        self.uploaded = 0
        # int32_t event
        # The event, one of:
            # none = 0
            # completed = 1
            # started = 2
            # stopped = 3
        self.event = 0
        # uint32_t ip Your ip address. Set to 0 if you want the tracker to use the sender of this UDP packet.
        self.ip = 0
        # uint32_t key A unique key that is randomized by the client.
        self.key = 0
        # int32_t num_want The maximum number of peers you want in the reply. Use -1 for default.
        self.num_want = -1
        # uint16_t port The port you're listening on.
        self.port = 8000

    def serialize(self):
        buffer = b""
        buffer += struct.pack("!q", self.connection_id)
        buffer += struct.pack("!i", self.action)
        buffer += struct.pack("!i", self.transaction_id)
        buffer += self.info_hash  # already byte enconded
        buffer += self.peer_id  # already byte enconded
        buffer += struct.pack("!q", self.downloaded)
        buffer += struct.pack("!q", self.left)
        buffer += struct.pack("!q", self.uploaded)
        buffer += struct.pack("!i", self.event)
        buffer += struct.pack("!I", self.ip)
        buffer += struct.pack("!I", self.key)
        buffer += struct.pack("!i", self.num_want)
        buffer += struct.pack("!H", self.port)
        return buffer

    def __str__(self):
        return f"connection_id: {self.connection_id}\n" + \
               f"action: {self.action}\n" + \
               f"transaction_id: {self.transaction_id}\n" + \
               f"info_hash: {self.info_hash}\n" + \
               f"peer_id: {self.peer_id}\n" + \
               f"downloaded: {self.downloaded}\n" + \
               f"left: {self.left}\n" + \
               f"uploaded: {self.uploaded}\n" + \
               f"event: {self.event}\n" + \
               f"ip: {self.ip}\n" + \
               f"key: {self.key}\n" + \
               f"num_want: {self.num_want}\n" + \
               f"port: {self.port}\n"

class Peer():

    def __init__(self, ip, port):
        # int32_t ip The ip of a peer in the swarm.
        self.ip = ip
        # uint16_t port The peer's listen port.
        self.port = port

    def __str__(self):
        return f"ip: {self.ip}\n" + \
                f"port: {self.port}\n"

class UdpTrackerAnnouncementResponse():

    def __init__(self):
        # int32_t action The action this is a reply to. Should in this case be 1 for announce. If 3 (for error) see errors. See actions.
        self.action = None
        # int32_t transaction_id Must match the transaction_id sent in the announce request.
        self.transaction_id = None
        # int32_t interval the number of seconds you should wait until re-announcing yourself.
        self.interval = None
        # int32_t leechers The number of peers in the swarm that has not finished downloading.
        self.leechers = None
        # int32_t seeders The number of peers in the swarm that has finished downloading and are seeding.
        self.seeders = None
        # The rest of the server reply is a variable number of the following structure:
        self.peers = []

    def deserialize(self, buffer):

        self.action = struct.unpack("!i", buffer[:4])[0]
        self.transaction_id = struct.unpack("!i", buffer[4:8])[0]
        self.interval = struct.unpack("!i", buffer[8:12])[0]
        self.leechers = struct.unpack("!i", buffer[12:16])[0]
        self.seeders = struct.unpack("!i", buffer[16:20])[0]
        peer_data = buffer[20:]
        peers = [peer_data[i:i+6] for i in range(0, len(peer_data), 6)]
        for peer in peers:
            ip = socket.inet_ntoa(peer[:4])
            port = struct.unpack("!H", peer[4:])[0]
            peer = Peer(ip, port)
            self.peers.append(peer)


    def __str__(self):
        return f"connection_id: {self.connection_id}\n"

if __name__ == "__main__":
    torrent = Torrent()
    # torrent.load_torrent("/Users/rot/Downloads/wired-cd.torrent")   # udp tracker
    torrent.load_torrent("/Users/rot/Downloads/big-buck-bunny.torrent")   # udp tracker
    # torrent.load_torrent("/Users/rot/Downloads/ubuntu.torrent")  # http tracker
    parsed_url = urlparse(torrent.tracker)

    import socket

    udp_tracker_conn = UdpTrackerConnection()
    connection_message = udp_tracker_conn.serialize()
    ip, port = socket.gethostbyname(parsed_url.hostname), parsed_url.port

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(connection_message, (ip, port))
        data = s.recv(4096)
        udp_tracker_conn.deserialize(data)
        udp_tracker_announce = UdpTrackerAnnouncement(udp_tracker_conn.connection_id,
            torrent._info_hash, torrent._peer_id)
        announce_message = udp_tracker_announce.serialize()
        s.sendto(announce_message, (ip, port))
        data = s.recv(4096)
        udp_tracker_announce_resp = UdpTrackerAnnouncementResponse()
        udp_tracker_announce_resp.deserialize(data)

        print(len(udp_tracker_announce_resp.peers))
        for peer in udp_tracker_announce_resp.peers:
            print(peer)

        # Attempt to connect to peers in order
        connected = False
        num_peers = len(udp_tracker_announce_resp.peers)
        attempt = 0
        socket_object = None
        while(not connected and attempt < num_peers):
            peer = udp_tracker_announce_resp.peers[attempt]
            try:
                print(f"Attempting connection to peer with IP {peer.ip}, using port {peer.port}")
                socket_object = socket.create_connection((peer.ip, peer.port), 2)
                socket_object.setblocking(False)
                connected = True
            except Exception as e:
                print(f"Failed to connect to peer ({peer.ip}, {peer.port}) - {e}")
            attempt += 1

        if socket_object is not None:
            print(f"Connection to peer with IP {peer.ip}, using port {peer.port} was successful!")
            handshake = PeerHandshake(torrent._info_hash, torrent._peer_id)
            # print(handshake)
            try:
                buffer = handshake.serialize()
                socket_object.send(buffer)
            except Exception as e:
                print(f"Failed to send handshake - {e}")
            finally:
                socket_object.close()
