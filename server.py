import os
import socket
import threading
import struct
import uuid
from enum import Enum

HOST = ''
DEFAULT_PORT = 1256
DEFAULT_PORT_FILE = "port.info"
PACKET_SIZE = 1024
SERVER_MAX_CONNECTIONS = 50
VERSION = 1
UNPACK_FORMAT = "16sBHI"
PACK_FORMAT = "!BHI"
REQUEST_HEADER_SIZE = 23
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

class Register:
    data_base = []

    def __init__(self, clients_name):
        if self.check_client_name(clients_name):
            self.clients_name = clients_name
            self.register_successful = True
            self.client_id = self.generate_id()
            Register.data_base.append(clients_name)

    def check_client_name(self,clients_name):
        if clients_name in Register.data_base:
            return False
        return True

    def generate_id(self):
        return uuid.uuid4().bytes

    def is_register_successful(self):
        return self.register_successful

    def get_client_id(self):
        return self.client_id
'''
Receives requests from the server and sends the response to the server  
'''

class ClientHandler:
    def __init__(self,request):
        self.request = Request(request)
        self.response = None
    # If registration succeeded, returns success code and the clients id, else returns the failure code and try again message
    def handle_registration(self):
        r1 = Register(self.request.payload)
        if r1.is_register_successful():
            payload = r1.get_client_id()
            return Response(VERSION,ResponseCodes.REGISTRATION_SUCCESS,payload.__sizeof__(),payload)
        payload = "Register failed, Please try again."
        return Response(VERSION,ResponseCodes.REGISTRATION_FAILED,payload.__sizeof__(),payload)
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
        return struct.pack(PACK_FORMAT, self.version, self.code, self.payload_size) + self.payload.encode("utf-8")

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
        header_size = len(data[:REQUEST_HEADER_SIZE])
        if header_size != REQUEST_HEADER_SIZE:
            raise ValueError(f"Invalid header size: {header_size}. {REQUEST_HEADER_SIZE} bytes expected.")

        client_id, version, code, payload_size = struct.unpack(UNPACK_FORMAT, data[:REQUEST_HEADER_SIZE])
        payload = data[REQUEST_HEADER_SIZE: REQUEST_HEADER_SIZE + payload_size].decode('utf-8')

        return {
            'client_id': client_id.decode('utf-8').strip(),
            'version': version,
            'code': code,
            'payload_size': payload_size,
            'payload': payload
        }

    @property
    def client_id(self):
        return self._client_id

    @property
    def version(self):
        return self._version

    @property
    def code(self):
        return self._code

    @property
    def payload_size(self):
        return self._payload_size

    @property
    def payload(self):
        return self._payload

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    @version.setter
    def version(self, value):
        self._version = value

    @code.setter
    def code(self, value):
        self._code = value

    @payload_size.setter
    def payload_size(self, value):
        self._payload_size = value

    @payload.setter
    def payload(self, value):
        self._payload = value


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
                    Client handler will take the request, analyze it and return the needed response object
                    '''


                    #TODO - data receiving needs correcting, first receive the header, extract payload size,
                    #TODO - then receive the the payload using the payload size

                    data = conn.recv(PACKET_SIZE)# Receive data
                    request = Request(data) # Translate data to request object
                    handler = ClientHandler(request) # Handle that request

                    request_code_to_handler = {
                        RequestCodes.REGISTRATION: handler.handle_registration,
                        RequestCodes.SENDING_PUBLIC_KEY: handler.handle_public_key,
                        RequestCodes.SIGN_IN: handler.handle_sign_in,
                        RequestCodes.SENDING_FILE: handler.handle_file_received,
                        RequestCodes.CRC_VALID: handler.handle_crc_valid,
                        RequestCodes.CRC_NOT_VALID: handler.handle_crc_not_valid,
                        RequestCodes.CRC_EXCEEDED_TRIES: handler.handle_crc_exceeded_tries,
                    }

                    error_message = "GENERAL ERROR: Something went wrong"
                    response = Response(VERSION, ResponseCodes.GENERAL_ERROR, error_message.__sizeof__(), error_message)
                    response = request_code_to_handler.get(request.code, lambda: response)()

                    conn.sendall(response.pack_response())


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
