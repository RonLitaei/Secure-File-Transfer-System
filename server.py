import os
import socket
import threading
import struct
import uuid
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from enum import Enum

HOST = ''
DEFAULT_PORT = 1256
DEFAULT_PORT_FILE = "port.info"
PACKET_SIZE = 1024
SERVER_MAX_CONNECTIONS = 50
VERSION = 1
UNPACK_FORMAT = "<16sBHI"
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
    data_base = {}

    def __init__(self, clients_name):
        if self.check_client_name(clients_name):
            self.clients_name = clients_name
            self.register_successful = True
            self.client_id = self.generate_id()
            Register.data_base.update({clients_name : self.client_id})
        else:
            self.register_successful = False

    def check_client_name(self,clients_name):
        if clients_name in Register.data_base:
            return False
        return True

    def generate_id(self):
        return uuid.uuid4().hex

    def is_register_successful(self):
        return self.register_successful

    def get_client_id(self):
        return self.client_id
'''
Receives requests from the server and sends the response to the server  
'''

class ClientHandler:
    error_message = b"GENERAL ERROR: Something went wrong"
    def __init__(self,request):
        self.request = request
        # Default response in the general error response
        self.response = Response(VERSION, ResponseCodes.GENERAL_ERROR, len(self.error_message),self.error_message)

    # If registration succeeded, returns success code and the clients id, else returns the failure code and try again message
    def handle_registration(self):
        r1 = Register(self.request.payload.decode('ascii').rstrip('\0'))
        if r1.is_register_successful():
            payload = r1.get_client_id()
            self.response = Response(VERSION,ResponseCodes.REGISTRATION_SUCCESS,len(payload),payload)
        else:
            payload = "Register failed, Please try again."
            self.response = Response(VERSION,ResponseCodes.REGISTRATION_FAILED,len(payload),payload)
    def handle_public_key(self):
        payload = b""
        encoded_name = self.request.payload[:255]
        name = encoded_name.decode('ascii').rstrip('\0')
        client_id = Register.data_base.get(name)

        if client_id is None:
            payload = b"Client id not found"
            #TODO - add these methods to Response
            #self.response.set_payloadsize(len(payload))
            #self.response.set_payload(payload)
            return

        #TODO - this can be written in a different function
        public_key_pem = self.request.payload[255:255 + 160]
        aes_key = get_random_bytes(32)
        public_key = RSA.import_key(public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        payload = bytes(client_id, 'ascii')
        payload += encrypted_aes_key
        self.response = Response(VERSION,ResponseCodes.PUBLIC_KEY_RECEIVED_SENDING_AES,len(payload),payload)
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
        if type(self.payload) != bytes:
            return struct.pack(PACK_FORMAT, self.version, self.code.value, self.payload_size) + self.payload.encode("ascii")
        return struct.pack(PACK_FORMAT, self.version, self.code.value, self.payload_size) + self.payload

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
# To use this class, first you must receive data that contains only the header using unpack_header,
# later set the payload.
# Payload is raw bytes, decode later in what you need
class Request:
    def __init__(self, data):
        unpacked_data = self.unpack_header(data)
        self.client_id = unpacked_data['client_id']
        self.version = unpacked_data['version']
        self.code = unpacked_data['code']
        self.payload_size = unpacked_data['payload_size']
        self.payload = None

    def __str__(self):
        return (f"Request(Client ID: {self.client_id}, Version: {self.version}, "
                f"Code: {self.code}, Payload Size: {self.payload_size}, "
                f"Payload: {self.payload})")

    # Unpacks header from raw data, should be REQUEST_HEADER_SIZE - 23 bytes
    def unpack_header(self, data):
        header_size = len(data[:REQUEST_HEADER_SIZE])
        if header_size != REQUEST_HEADER_SIZE:
            raise ValueError(f"Invalid header size: {header_size}. {REQUEST_HEADER_SIZE} bytes expected.")
        client_id, version, code, payload_size = struct.unpack(UNPACK_FORMAT, data)
        try:
            code_enum = RequestCodes(code)
        except ValueError:
            raise ValueError(f"Invalid request code: {code}")

        return {
            'client_id': client_id.decode('ascii').strip(),
            'version': version,
            'code': code_enum,
            'payload_size': payload_size,
        }

    # sets the payload in bytes, make sure to pass the whole data and not chunks of it
    def set_payload(self, data):
        if len(data) != self.payload_size:
            raise ValueError(f"Incomplete payload: expected {self.payload_size} bytes, got {len(data)} bytes.")
        self.payload = data
    '''
    @property
    def client_id(self):
        return self.client_id

    @property
    def version(self):
        return self.version

    @property
    def code(self):
        return self.code

    @property
    def payload_size(self):
        return self.payload_size

    @property
    def payload(self):
        return self.payload

    @client_id.setter
    def client_id(self, value):
        self.client_id = value

    @version.setter
    def version(self, value):
        self.version = value

    @code.setter
    def code(self, value):
        self.code = value

    @payload_size.setter
    def payload_size(self, value):
        self.payload_size = value

    @payload.setter
    def payload(self, value):
        self.payload = value
'''

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

                    # Receive the header first
                    header = conn.recv(REQUEST_HEADER_SIZE)
                    if not header:
                        print(f"Stopped receiving communication from client {addr}")
                        break
                    request = Request(header)  # Translate data (header at this point) to request object

                    # Time to initialize the payload
                    payload = b""
                    bytes_received = 0
                    while bytes_received < request.payload_size:
                        bytes_to_read = min(PACKET_SIZE, request.payload_size - bytes_received)
                        chunk = conn.recv(bytes_to_read)
                        if not chunk:
                            break
                        payload += chunk
                        bytes_received += len(chunk)

                    request.set_payload(payload)
                    handler = ClientHandler(request)

                    request_code_to_handler = {
                        RequestCodes.REGISTRATION: handler.handle_registration,
                        RequestCodes.SENDING_PUBLIC_KEY: handler.handle_public_key,
                        RequestCodes.SIGN_IN: handler.handle_sign_in,
                        RequestCodes.SENDING_FILE: handler.handle_file_received,
                        RequestCodes.CRC_VALID: handler.handle_crc_valid,
                        RequestCodes.CRC_NOT_VALID: handler.handle_crc_not_valid,
                        RequestCodes.CRC_EXCEEDED_TRIES: handler.handle_crc_exceeded_tries,
                    }

                    request_code_to_handler.get(request.code)()
                    print(request.payload)
                    conn.sendall(handler.response.pack_response())


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
