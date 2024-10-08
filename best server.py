import socket
import threading
import struct
import uuid
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from enum import Enum
import logging
from pathlib import Path

# Constants
HOST = ''
DEFAULT_PORT = 1256
DEFAULT_PORT_FILE = "port.info"
PACKET_SIZE = 1024
SERVER_MAX_CONNECTIONS = 50
VERSION = 3
UNPACK_HEADER_FORMAT = "<BHI"  # Network byte order (big-endian)
PACK_HEADER_FORMAT = "!BHI"
REQUEST_HEADER_SIZE = 23
MAX_REQUEST_SIZE = 1073741847  # 1GB payload + 23 bytes for header
AES_KEY_SIZE = 32  # 256 bits
AES_BLOCK_SIZE = 16  # 128 bits

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('server.log')
    ]
)
logger = logging.getLogger(__name__)


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


@dataclass
class ClientInfo:
    client_id: bytes
    aes_key: Optional[bytes] = None
    public_key: Optional[bytes] = None


class SecurityManager:
    def __init__(self):
        self.clients: Dict[str, ClientInfo] = {}
        self._lock = threading.Lock()

    def register_client(self, client_name: str) -> Optional[bytes]:
        with self._lock:
            if client_name in self.clients:
                return None
            client_id = uuid.uuid4().bytes
            self.clients[client_name] = ClientInfo(client_id=client_id)
            return client_id

    def get_client_info(self, client_name: str) -> Optional[ClientInfo]:
        with self._lock:
            return self.clients.get(client_name)

    def get_client_name(self, client_id: bytes = None, public_key: bytes = None) -> Optional[str]:
        with self._lock:
            for client_name, client_info in self.clients.items():
                if client_info.client_id == client_id or (
                        public_key is not None and client_info.public_key == public_key):
                    return client_name
            return None

    def set_client_keys(self, client_name: str, public_key: bytes) -> Tuple[bytes, bytes]:
        aes_key = get_random_bytes(AES_KEY_SIZE)
        rsa_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        with self._lock:
            if client_name in self.clients:
                self.clients[client_name].aes_key = aes_key
                self.clients[client_name].public_key = public_key

        return encrypted_aes_key, aes_key

class FileReceiver:
    HEADER_SIZE = 267  # 4 + 4 + 2 + 2 + 255

    def __init__(self):
        self.current_file_infos = {}  # Dictionary to store file info for each client
        self.lock = threading.Lock()  # Thread safety for shared resources

    def decrypt_data(self, encrypted_data: bytes, aes_key: bytes) -> bytes:
        iv = b'\x00' * 16
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        return cipher.decrypt(encrypted_data)

    def parse_header(self, header_data: bytes) -> tuple:
        if len(header_data) != self.HEADER_SIZE:
            raise ValueError(f"Invalid header size: {len(header_data)}")

        encrypted_size, original_size = struct.unpack('<II', header_data[:8])
        packet_num, total_packets = struct.unpack('<HH', header_data[8:12])
        filename = header_data[12:267].rstrip(b'\x00').decode('ascii')

        return encrypted_size, original_size, packet_num, total_packets, filename

    def handle_file_packet(self, packet_data: bytes, client_id: str, aes_key: bytes) -> bool:
        try:
            header = packet_data[:self.HEADER_SIZE]
            encrypted_size, original_size, packet_num, total_packets, filename = self.parse_header(header)
            encrypted_content = packet_data[self.HEADER_SIZE:self.HEADER_SIZE + encrypted_size]

            with self.lock:
                if client_id not in self.current_file_infos:
                    self.current_file_infos[client_id] = {
                        'filename': filename,
                        'original_size': original_size,
                        'total_packets': total_packets,
                        'received_packets': {},
                        'aes_key': aes_key
                    }

                self.current_file_infos[client_id]['received_packets'][packet_num] = encrypted_content

            logger.info(f"Client {client_id}: Received packet {packet_num + 1}/{total_packets} for file {filename}")

            # Check if file is complete
            with self.lock:
                if len(self.current_file_infos[client_id]['received_packets']) == total_packets:
                    self.save_complete_file(client_id)
                    return True

            return False

        except Exception as e:
            logger.error(f"Error processing packet for client {client_id}: {e}")
            return False

    def save_complete_file(self, client_id: str):
        with self.lock:
            if client_id not in self.current_file_infos:
                return

            try:
                file_info = self.current_file_infos[client_id]
                all_encrypted_data = b''
                for i in range(file_info['total_packets']):
                    if i not in file_info['received_packets']:
                        raise ValueError(f"Missing packet {i}")
                    all_encrypted_data += file_info['received_packets'][i]

                decrypted_data = self.decrypt_data(all_encrypted_data, file_info['aes_key'])
                decrypted_data = decrypted_data[:file_info['original_size']]

                output_filename = f"received_{client_id}_{file_info['filename']}"
                with open(output_filename, 'wb') as f:
                    f.write(decrypted_data)

                logger.info(f"File saved successfully as {output_filename} for client {client_id}")
                del self.current_file_infos[client_id]

            except Exception as e:
                logger.error(f"Error saving complete file for client {client_id}: {e}")


class FileManager:
    def __init__(self, base_path: Path = Path("received_files")):
        self.base_path = base_path
        self.base_path.mkdir(exist_ok=True)
        self.file_receiver = FileReceiver()

    def save_file(self, filename: str, data: bytes, client_id: str) -> Path:
        safe_filename = Path(filename).name  # Remove any path components
        client_folder = self.base_path / client_id
        client_folder.mkdir(exist_ok=True)

        file_path = client_folder / safe_filename
        file_path.write_bytes(data)
        return file_path

class Server:
    def __init__(self, host: str = HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self.security_manager = SecurityManager()
        self.file_manager = FileManager()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.active = False
        self._lock = threading.Lock()

    def start(self):
        self.sock.bind((self.host, self.port))
        self.sock.listen(SERVER_MAX_CONNECTIONS)
        self.active = True
        logger.info(f"Server listening on {self.host}:{self.port}")

        try:
            while self.active:
                conn, addr = self.sock.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True
                )
                client_thread.start()
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self.shutdown()

    def shutdown(self):
        logger.info("Shutting down server...")
        self.active = False
        self.sock.close()
        logger.info("Server shutdown complete")

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]):
        client_addr = f"{addr[0]}:{addr[1]}"
        logger.info(f"New connection from {client_addr}")

        try:
            while self.active:
                request = self._receive_request(conn)
                if request is None:
                    break

                response = self._process_request(request, client_addr)
                self._send_response(conn, response)
        except Exception as e:
            logger.error(f"Error handling client {client_addr}: {e}")
        finally:
            conn.close()
            logger.info(f"Connection closed for {client_addr}")

    def _receive_request(self, conn: socket.socket) -> Optional[dict]:
        try:
            header = self._receive_exact(conn, REQUEST_HEADER_SIZE)
            if not header:
                return None

            client_id = header[:16]
            version, code, payload_size = struct.unpack(UNPACK_HEADER_FORMAT, header[16:])

            if payload_size > MAX_REQUEST_SIZE:
                logger.error(f"Payload size too large: {payload_size}")
                return None

            payload = self._receive_exact(conn, payload_size) if payload_size > 0 else b''

            return {
                'client_id': client_id,
                'version': version,
                'code': RequestCodes(code),
                'payload': payload
            }
        except Exception as e:
            logger.error(f"Error receiving request: {e}")
            return None

    def _process_request(self, request: dict, client_addr: str) -> dict:
        try:
            handlers = {
                RequestCodes.REGISTRATION: self._handle_registration,
                RequestCodes.SENDING_PUBLIC_KEY: self._handle_public_key,
                RequestCodes.SIGN_IN: self._handle_sign_in,
                RequestCodes.SENDING_FILE: self._handle_file
            }

            handler = handlers.get(request['code'], self._handle_unknown)
            return handler(request, client_addr)
        except Exception as e:
            logger.error(f"Error processing request: {e}")
            return self._create_error_response("Internal server error")

    def _send_response(self, conn: socket.socket, response: dict):
        try:
            header = struct.pack(
                PACK_HEADER_FORMAT,
                response['version'],
                response['code'].value,
                len(response['payload'])
            )
            conn.sendall(header + response['payload'])
        except Exception as e:
            logger.error(f"Error sending response: {e}")

    @staticmethod
    def _receive_exact(conn: socket.socket, size: int) -> Optional[bytes]:
        data = bytearray()
        while len(data) < size:
            packet = conn.recv(min(size - len(data), PACKET_SIZE))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)

    def _handle_registration(self, request: dict, client_addr: str) -> dict:
        client_name = request['payload'].decode('ascii').rstrip('\0')
        client_id = self.security_manager.register_client(client_name)

        if client_id:
            return {
                'version': VERSION,
                'code': ResponseCodes.REGISTRATION_SUCCESS,
                'payload': client_id
            }
        else:
            return self._create_error_response("Registration failed")

    def _handle_public_key(self, request: dict, client_addr: str) -> dict:
        try:
            client_name = request['payload'][:255].decode('ascii').rstrip('\0')
            public_key = request['payload'][255:415]

            encrypted_aes_key, _ = self.security_manager.set_client_keys(client_name, public_key)
            client_info = self.security_manager.get_client_info(client_name)

            if client_info:
                payload = client_info.client_id + encrypted_aes_key
                return {
                    'version': VERSION,
                    'code': ResponseCodes.PUBLIC_KEY_RECEIVED_SENDING_AES,
                    'payload': payload
                }
        except Exception as e:
            logger.error(f"Error handling public key: {e}")

        return self._create_error_response("Failed to process public key")

    def _handle_sign_in(self, request: dict, client_addr: str) -> dict:
        try:
            client_name = request['payload'][:255].decode('ascii').rstrip('\0')
            client_info = self.security_manager.get_client_info(client_name)

            if client_info and client_info.aes_key and client_info.public_key:
                # Re-encrypt the AES key with the client's public key
                rsa_key = RSA.import_key(client_info.public_key)
                cipher_rsa = PKCS1_OAEP.new(rsa_key)
                encrypted_aes_key = cipher_rsa.encrypt(client_info.aes_key)

                payload = client_info.client_id + encrypted_aes_key

                return {
                    'version': VERSION,
                    'code': ResponseCodes.SIGN_IN_SUCCESS,
                    'payload': payload
                }
            else:
                logger.warning(f"Sign in failed for {client_name}: missing client info or keys")
                return self._create_error_response("Sign in failed: client not properly registered")

        except Exception as e:
            logger.error(f"Error handling sign in: {e}")
            return self._create_error_response("Sign in failed: internal error")

    def _handle_file(self, request: dict, client_addr: str) -> dict:
        try:
            current_file = None
            expected_packets = 0
            received_packets = 0

            client_id = request.get('client_id')
            client_name = self.security_manager.get_client_name(client_id)
            aes_key = self.security_manager.get_client_info(client_name).aes_key
            if client_name is None or aes_key is None:
                logger.error(f"Client {client_id} not registered or has no aes key")
                return self._create_error_response("Client not registered or no AES key")

            while True:
                # Receive header for this packet
                header_data = self._receive_exact(self.sock, FileReceiver.HEADER_SIZE)
                if not header_data:
                    break

                # Parse header
                content_size, orig_file_size, packet_num, total_packets, filename \
                    = FileReceiver.parse_header(header_data)

                if current_file is None:
                    current_file = filename
                    expected_packets = total_packets
                    logger.info(f"Starting transfer of file: {filename}, expecting {total_packets} packets")

                # Receive the packet content
                # The last message from the client needs to be padded to PACKET_SIZE
                encrypted_content = self._receive_exact(self.sock, content_size / total_packets)
                if not encrypted_content:
                    logger.error(f"Failed to receive packet content for packet {packet_num + 1}")
                    break

                # Process this packet
                full_packet = header_data + encrypted_content
                file_complete = self.file_manager.file_receiver.handle_file_packet(full_packet, client_id, aes_key)

                received_packets += 1
                logger.debug(f"Received packet {packet_num + 1}/{total_packets} for file: {filename}")

                if file_complete or received_packets == expected_packets:
                    logger.info(f"File transfer completed for {filename}")
                    break

            return {
                'version': VERSION,
                'code': ResponseCodes.FILE_RECEIVED,
                'payload': b"File received successfully"
            }

        except Exception as e:
            logger.error(f"Error handling file: {e}")
            return self._create_error_response("Failed to process file")

    def _handle_unknown(self, request: dict, client_addr: str) -> dict:
        return self._create_error_response(f"Unknown request code: {request['code']}")

    @staticmethod
    def _create_error_response(message: str) -> dict:
        return {
            'version': VERSION,
            'code': ResponseCodes.GENERAL_ERROR,
            'payload': message.encode('ascii')
        }


def main():
    port = DEFAULT_PORT
    port_file = Path(DEFAULT_PORT_FILE)

    if port_file.exists():
        try:
            port = int(port_file.read_text().strip())
            if not (0 <= port <= 65535):
                port = DEFAULT_PORT
        except ValueError:
            port = DEFAULT_PORT

    server = Server(port=port)
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Server stopping due to keyboard interrupt...")
        server.shutdown()


if __name__ == "__main__":
    main()
