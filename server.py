from minecraft.networking.packets import clientbound, serverbound
from minecraft.networking import connection
import socket
from minecraft.networking import types
import zlib
from minecraft.networking import packets
import json
import uuid
import hashlib
import struct


class Server():
    def __init__(self, debug):

        self.context = connection.ConnectionContext(protocol_version=757)

        self.packets_handshake = {
            p.get_id(self.context): p for p in
            serverbound.handshake.get_packets(self.context)}

        self.packets_login = {
            p.get_id(self.context): p for p in
            serverbound.login.get_packets(self.context)}

        self.packets_playing = {
            p.get_id(self.context): p for p in
            serverbound.play.get_packets(self.context)}

        self.packets_status = {
            p.get_id(self.context): p for p in
            serverbound.status.get_packets(self.context)}

        self.compression_enabled = False
        self.compression_threshold = 256
        self.minecraft_version = "1.18.1"

        self.debug = debug

        self.user_connected = False

        self.read_buffer = []
        self.send_buffer = []

    def write_packet(self, packet):
        packet.context = self.context
        if self.debug:
            print('[S -> U] %s' % packet.packet_name)
        packet.write(self.socket, **(
            {'compression_threshold': self.compression_threshold}
            if self.compression_enabled else {}))

    def read_packet(self):
        buffer = self._read_packet_buffer()
        packet_id = types.VarInt.read(buffer)
        if packet_id in self.packets:
            packet = self.packets[packet_id](self.context)
            packet.read(buffer)
        else:
            packet = packets.Packet(self.context, id=packet_id)
        if self.debug:
            print('[U -> S] %s' % packet.packet_name)
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
        packet = self.read_packet()
        if packet.next_state == 1:
            self.status()
        elif packet.next_state == 2:
            self.handshake_to_play(packet)

    def status(self):
        pass

    def handshake_to_play(self, packet):
        if self.context.protocol_version == packet.protocol_version:
            return self.login()
        elif self.context.protocol_earlier(packet.protocol_version):
            msg = "Outdated server! I'm still on %s" \
                  % self.minecraft_version
        else:
            msg = 'Outdated client! Please use %s' \
                  % self.minecraft_version
        self.write_packet(clientbound.login.DisconnectPacket(
            json_data=json.dumps({'text': msg})))

    def login(self):
        self.packets = self.packets_login
        packet = self.read_packet()
        if self.compression_threshold is not None:
            self.write_packet(clientbound.login.SetCompressionPacket(
                threshold=self.compression_threshold))
            self.compression_enabled = True

        self.user_name = packet.name
        self.user_uuid = uuid.UUID(bytes=hashlib.md5(
            ('OfflinePlayer:%s' % self.user_name).encode('utf8')).digest())
        self.write_packet(clientbound.login.LoginSuccessPacket(
            UUID=str(self.user_uuid), Username=self.user_name))
        self.playing()

    def playing(self):
        self.packets = self.packets_playing
        self.user_connected = True
        print("User Logged in as " + self.user_name + " (" + str(self.user_uuid) + ")")

    def socket_creation(self):
        self.listen_socket = socket.socket()
        self.listen_socket.bind(('localhost', 25565))
        self.listen_socket.listen(1)
        client_socket, addr = self.listen_socket.accept()
        self.socket_file = client_socket.makefile('rb', 0)
        self.socket = client_socket
        print('[ ++ ] User %s connected.' % (addr,))
        self.handshake()

    def connected(self):
        return self.user_connected

    def read_packets(self):
        while True:
            buffer = self._read_packet_buffer()
            packet_id = types.VarInt.read(buffer)
            if packet_id in self.packets:
                packet = self.packets[packet_id](self.context)
                packet.read(buffer)
                if self.debug:
                    print('[U -> S] %s' % packet.packet_name)
            else:
                packet = [packet_id]
                packet.append(buffer.read())
            self.read_buffer.append(packet)

    def send_packets(self):
        while True:
            if len(self.send_buffer) > 0:
                if isinstance(self.send_buffer[0], list):
                    value = self.send_buffer[0][0]
                    out = bytes()
                    while True:
                        byte = value & 0x7F
                        value >>= 7
                        out += struct.pack("B", byte | (0x80 if value > 0 else 0))
                        if value == 0:
                            break
                    self.socket.sendall(out+self.send_buffer[0][1])

                else:
                    if self.debug:
                        print('[S -> U] %s' % self.send_buffer[0].packet_name)
                    self.write_packet(self.send_buffer[0])
                self.send_buffer.pop(0)
