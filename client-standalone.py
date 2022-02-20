import sys
import re
from minecraft.networking.packets import clientbound, serverbound
from minecraft.networking import connection
from minecraft.networking import types
import zlib
from minecraft.networking import packets
import socket
import encryption
import authentication


client_connected = False
debug = False


class PacketNotExpected(Exception):
    pass


class Client():
    def __init__(self):
        self.options = {
            "username": "DNGreenBean",
            "server": "localhost:25566",
            "offline": False,
            "dump_packets": False,
            "dump_unknown": False,
            "address": "",
            "port": ""
        }
        self.context = connection.ConnectionContext(protocol_version=757)

        self.packets_handshake = {
            p.get_id(self.context): p for p in
            clientbound.handshake.get_packets(self.context)}

        self.packets_login = {
            p.get_id(self.context): p for p in
            clientbound.login.get_packets(self.context)}

        self.packets_playing = {
            p.get_id(self.context): p for p in
            clientbound.play.get_packets(self.context)}

        self.packets_status = {
            p.get_id(self.context): p for p in
            clientbound.status.get_packets(self.context)}

        self.compression_enabled = False
        self.compression_threshold = 256

    def read_packet(self):
        buffer = self._read_packet_buffer()
        packet_id = types.VarInt.read(buffer)
        if packet_id in self.packets:
            packet = self.packets[packet_id](self.context)
            packet.read(buffer)
        else:
            packet = packets.Packet(self.context, id=packet_id)
        if debug:
            print('[S -> C] %s' % packet.packet_name)
        return packet

    def _read_packet_buffer(self):
        length = types.VarInt.read(self.socket_file)
        buffer = packets.PacketBuffer()
        while len(buffer.get_writable()) < length:
            data = self.socket_file.read(length - len(buffer.get_writable()))
            buffer.send(data)
        buffer.reset_cursor()
        if self.compression_enabled:
            data_length = types.VarInt.read(buffer)
            if data_length > 0:
                data = zlib.decompress(buffer.read())
                assert len(data) == data_length, \
                    '%s != %s' % (len(data), data_length)
                buffer.reset()
                buffer.send(data)
                buffer.reset_cursor()
        return buffer

    def handshake(self):
        self.packets = self.packets_handshake
        packet = serverbound.handshake.HandShakePacket()
        packet.protocol_version = 757
        packet.server_address = self.options["address"]
        packet.server_port = self.options["port"]
        packet.next_state = 2
        packet.context = self.context
        if debug:
            print('[C -> S] %s' % packet.packet_name)
        packet.write(self.socket)

    def login(self):
        # Login Start
        self.packets = self.packets_login
        packet = serverbound.login.LoginStartPacket()
        packet.name = self.options["username"]
        packet.context = self.context
        if debug:
            print('[C -> S] %s' % packet.packet_name)
        packet.write(self.socket)

        # Authentication
        encryption_request = self.read_packet()
        sharedsecret = encryption.generate_shared_secret()

        verifyhash = encryption.generate_verification_hash(
            encryption_request.server_id, sharedsecret, encryption_request.public_key)
        auth_token = authentication.get_mc_auth_token()
        authentication.join(verifyhash, auth_token)

        encryptverify, encryptsecret = encryption.encrypt_token_and_secret(
            encryption_request.public_key, encryption_request.verify_token, sharedsecret)

        # Send Encryption Response
        packet = serverbound.login.EncryptionResponsePacket()
        packet.shared_secret = encryptsecret
        packet.verify_token = encryptverify
        packet.context = self.context
        if debug:
            print('[C -> S] %s' % packet.packet_name)
        packet.write(self.socket)

        # Encrypt Socket
        cipher = encryption.create_AES_cipher(sharedsecret)
        encryptor = cipher.encryptor()
        decryptor = cipher.decryptor()
        self.socket = encryption.EncryptedSocketWrapper(self.socket, encryptor, decryptor)
        self.socket_file = encryption.EncryptedFileObjectWrapper(self.socket_file, decryptor)

        # Compression Threshold
        compression = self.read_packet()
        if not compression.packet_name == "set compression":
            raise PacketNotExpected
        self.compression_threshold = compression.threshold
        self.compression_enabled = True

        # Login Success
        login_success = self.read_packet()
        if not login_success.packet_name == "login success":
            raise PacketNotExpected
        print("Connected to " + self.options["address"] + " at port " + str(
            self.options["port"]) + " as " + login_success.Username + " (" + login_success.UUID + ")")

    def play_chat_state(self):
        while True:
            try:
                # Input
                text = input()
                # Respawn
                if text == "/respawn":
                    print("respawning...")
                    packet = serverbound.play.ClientStatusPacket()
                    packet.action_id = serverbound.play.ClientStatusPacket.RESPAWN
                    packet.context = self.context
                    if debug:
                        print('[C -> S] %s' % packet.packet_name)
                    packet.write(self.socket, **(
                        {'compression_threshold': self.compression_threshold}
                        if self.compression_enabled else {}))
                # Chatting
                else:
                    packet = serverbound.play.ChatPacket()
                    packet.message = text
                    packet.context = self.context
                    if debug:
                        print('[C -> S] %s' % packet.packet_name)
                    packet.write(self.socket, **(
                        {'compression_threshold': self.compression_threshold}
                        if self.compression_enabled else {}))
            # Exit
            except KeyboardInterrupt:
                print("Bye!")
                sys.exit()

    def socket_creation(self):
        match = re.match(r"((?P<host>[^\[\]:]+)|\[(?P<addr>[^\[\]]+)\])"
                         r"(:(?P<port>\d+))?$", self.options["server"])
        if match is None:
            raise ValueError("Invalid server address: " + self.options["server"])
        self.options["address"] = match.group("host") or match.group("addr")
        self.options["port"] = int(match.group("port") or 25565)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.options["address"], self.options["port"]))
        self.socket_file = self.socket.makefile("wrb", 0)

    def main(self):
        global client_connected
        self.socket_creation()
        self.handshake()
        self.login()
        client_connected = True


client = Client()
client.main()
