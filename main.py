from minecraft.networking.packets import clientbound, serverbound
from minecraft.networking import connection
from minecraft.networking import types
from minecraft.networking import packets
import socket
import server
import client
import threading


debug = True
client_connected = False
user_connected = False

user_to_client = server.Server(debug)

client_to_server = client.Client(debug)

user_to_client.socket_creation()

while not user_to_client.connected():
    pass

client_to_server.socket_creation()

while not client_to_server.connected():
    pass


user_to_server_thread = threading.Thread(target=user_to_client.read_packets())
server_to_user_thread = threading.Thread(target=user_to_client.send_packets())
client_to_server_thread = threading.Thread(target=client_to_server.send_packets())
server_to_client_thread = threading.Thread(target=client_to_server.read_packets())

while True:
    if len(user_to_client.read_buffer) > 0:
        client_to_server.send_buffer.append(user_to_client.read_buffer[0])
        user_to_client.read_buffer.pop(0)

    if len(client_to_server.read_buffer) > 0:
        user_to_client.send_buffer.append(client_to_server.read_buffer[0])
        client_to_server.read_buffer.pop(0)
