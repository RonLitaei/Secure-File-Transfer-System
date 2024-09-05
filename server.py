import os
import socket
import threading
import struct
from enum import Enum

HOST = ''
DEFAULT_PORT = 1256
DEFAULT_PORT_FILE = "port.info"
PACKET_SIZE = 1024
SERVER_MAX_CONNECTIONS = 50
VERSION = 0
FORMAT = "16s B H I"
MIN_REQUEST_SIZE = 23
MAX_REQUEST_SIZE = 1073741847 #1GB payload + 23 bytes for the header

def handle_exceptions(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError:
            return None
    return wrapper

class RequestCodes(Enum):
    REGISTRATION = 825
    SENDING_PUBLIC_KEY = 826
    SIGN_IN = 827
    SENDING_FILE = 828
    CRC_VALID = 900
    CRC_NOT_VALID = 901
    CRC_EXCEEDED_TRIES = 902

class ResponseCodes(Enum):
    REGISTRATION_SUCCESS = 1600
    REGISTRATION_FAILED = 1601
    PUBLIC_KEY_RECEIVED_SENDING_AES = 1602
    FILE_RECEIVED = 1603
    MESSAGE_RECEIVED = 1604
    SIGN_IN_SUCCESS = 1605
    SIGN_IN_FAILED = 1606
    GENERAL_ERROR = 1607

'''
Receives requests from the server and sends the response to the server  
'''

class ClientHandler:
    def __init__(self,request):
        self.request = Request(request)
        self.response = None
    def handle_registration(self):
        pass
    def handle_public_key(self):
        pass
    def handle_sign_in(self):
        pass
    def handle_file_received(self):
        pass
    def handle_crc_valid(self):
        pass
    def handle_crc_not_valid(self):
        pass
    def handle_crc_exceeded_tries(self):
        pass


'''
 +---------------+----------+-----------------------------------------------------+
 | Field         | Size     | Description                                         |
 +---------------+----------+-----------------------------------------------------+
 | Version       | 1 byte   | Client version number                               |
 | Code          | 2 bytes  | Request code                                        |
 | Payload size  | 4 bytes  | Size of the request content                         | 
 +---------------+----------+-----------------------------------------------------+
 | Payload       | Variable | Content of the request, varies based on the request |
 +---------------+----------+-----------------------------------------------------+
'''
class Response:
    def __init__(self, version, code, payload_size, payload):
        self.version = version
        self.code = code
        self.payload_size = payload_size
        self.payload = payload

    def pack_response(self):
        return struct.pack(FORMAT, self.version, self.code, self.payload_size, self.payload)

'''
 +---------------+----------+-----------------------------------------------------+
 | Field         | Size     | Description                                         |
 +---------------+----------+-----------------------------------------------------+
 | Client ID     | 16 bytes | Unique identifier for each client                   | 
 | Version       | 1 byte   | Client version number                               |
 | Code          | 2 bytes  | Request code                                        |
 | Payload size  | 4 bytes  | Size of the request content                         | 
 +---------------+----------+-----------------------------------------------------+
 | Payload       | Variable | Content of the request, varies based on the request |
 +---------------+----------+-----------------------------------------------------+
'''
class Request:
    def __init__(self, data):
        unpacked_data = self.unpack_request(data)
        self.client_id = unpacked_data['client_id']
        self.version = unpacked_data['version']
        self.code = unpacked_data['code']
        self.payload_size = unpacked_data['payload_size']
        self.payload = unpacked_data['payload']

    def __str__(self):
        return (f"Request(Client ID: {self.client_id}, Version: {self.version}, "
                f"Code: {self.code}, Payload Size: {self.payload_size}, "
                f"Payload: {self.payload})")

    @handle_exceptions
    def unpack_request(self, data):
        header_size = struct.calcsize(FORMAT)

        if header_size < MIN_REQUEST_SIZE:
            raise ValueError(f"Request size too small - {header_size}, minimum is {MIN_REQUEST_SIZE}")
        if header_size > MAX_REQUEST_SIZE:
            raise ValueError(f"Request size too large - {header_size}, maximum is {MAX_REQUEST_SIZE}")

        client_id, version, code, payload_size = struct.unpack(FORMAT, data[:header_size])
        payload = data[header_size: header_size + payload_size].decode('utf-8')

        return {
            'client_id': client_id.decode('utf-8').strip(),
            'version': version,
            'code': code,
            'payload_size': payload_size,
            'payload': payload
        }

'''
Class Server - handles client connections.
Can be started, shutdown and show its status.
Using ipv4 and TCP/IP
'''
class Server:
    # PORT and HOST must be handled properly prior to server object initialization
    def __init__(self, HOST, PORT):
        self.HOST = HOST
        self.PORT = PORT
        self.VERSION = VERSION
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.active = False

    def handle_client(self, conn, addr):
        with conn:
            print('Connected by', addr)
            try:
                while self.active:
                    '''
                    Create a client handler object
                    Client handler will take the request, analyze it and return the needed response code
                    '''
                    data = conn.recv(PACKET_SIZE)
                    conn.sendall(b"Request received and processed")

            except (ConnectionResetError, ConnectionAbortedError):
                print(f"Client {addr} issued disconnect")
            except Exception as err:
                print(f"Error while handling client {addr}: {err}")
            finally:
                print(f"Server disconnecting from {addr}")

    # Shuts down the server
    def shutdown(self):
        self.active = False
        if self.sock:
            self.sock.close()

    # Starting the server while accepting connections from multiple clients
    def startup(self):
        try:
            self.sock.bind((self.HOST, self.PORT))
            self.sock.listen(SERVER_MAX_CONNECTIONS)
            self.active = True
            print(f"Server started on {self.HOST}: {self.PORT}")
            while self.active:
                conn, addr = self.sock.accept()
                thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                thread.start()

        except Exception as err:
            print(f"ERROR: {err}")
        finally:
            self.shutdown()
            print(f"Server disconnected from {self.HOST}: {self.PORT} and is now offline")

    # Returns the status of the server
    def status(self):
        return self.active

# Safely opens a file for reading only
def open_safe(file):
    if os.path.isfile(file):
        f = open(file, 'r')
        if f.readable():
            return f
        f.close()
    return None

def analyze_port(file):
    f = open_safe(file)
    if f:
        port = f.readline().strip()
        f.close()
        if port.isdigit():
            port = int(port)
            if 0 <= port <= 65535:
                return port
    return DEFAULT_PORT


if __name__ == "__main__":
    port = analyze_port(DEFAULT_PORT_FILE)
    server = Server("localhost", port)
    server.startup()
    server.shutdown()