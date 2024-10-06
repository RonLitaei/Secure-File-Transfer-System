import socket
import struct
from Crypto.Cipher import AES
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FileReceiver:
    HEADER_SIZE = 267  # 4 + 4 + 2 + 2 + 255

    def __init__(self, aes_key: bytes):
        self.aes_key = aes_key
        self.received_packets = {}
        self.current_file_info = None

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        iv = b'\x00' * 16  # Using the same zero IV as the C++ code
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return cipher.decrypt(encrypted_data)

    def parse_header(self, header_data: bytes) -> tuple:
        if len(header_data) != self.HEADER_SIZE:
            raise ValueError(f"Invalid header size: {len(header_data)}")

        encrypted_size, original_size = struct.unpack('<II', header_data[:8])
        packet_num, total_packets = struct.unpack('<HH', header_data[8:12])
        filename = header_data[12:267].rstrip(b'\x00').decode('utf-8')

        return encrypted_size, original_size, packet_num, total_packets, filename

    def handle_file_packet(self, packet_data: bytes) -> bool:
        try:
            # Parse header
            header = packet_data[:self.HEADER_SIZE]
            encrypted_size, original_size, packet_num, total_packets, filename = self.parse_header(header)

            # Extract encrypted content
            encrypted_content = packet_data[self.HEADER_SIZE:]

            # Update or create file info
            if self.current_file_info is None:
                self.current_file_info = {
                    'filename': filename,
                    'encrypted_size': encrypted_size,
                    'original_size': original_size,
                    'total_packets': total_packets,
                    'received_packets': {}
                }

            # Store packet
            self.current_file_info['received_packets'][packet_num] = encrypted_content

            logger.info(f"Received packet {packet_num + 1}/{total_packets} for file {filename}")

            # Check if we have all packets
            if len(self.current_file_info['received_packets']) == total_packets:
                self.save_complete_file()
                return True

            return False

        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return False

    def save_complete_file(self):
        if not self.current_file_info:
            return

        try:
            # Combine all packets
            all_encrypted_data = b''
            for i in range(self.current_file_info['total_packets']):
                if i not in self.current_file_info['received_packets']:
                    raise ValueError(f"Missing packet {i}")
                all_encrypted_data += self.current_file_info['received_packets'][i]

            # Decrypt the complete file
            decrypted_data = self.decrypt_data(all_encrypted_data)

            # Trim to original size
            decrypted_data = decrypted_data[:self.current_file_info['original_size']]

            # Save to file
            output_filename = f"received_{self.current_file_info['filename']}"
            with open(output_filename, 'wb') as f:
                f.write(decrypted_data)

            logger.info(f"File saved successfully as {output_filename}")

            # Clear current file info
            self.current_file_info = None

        except Exception as e:
            logger.error(f"Error saving complete file: {e}")


class FileServer:
    def __init__(self, host: str, port: int, aes_key: bytes):
        self.host = host
        self.port = port
        self.file_receiver = FileReceiver(aes_key)

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            logger.info(f"Server listening on {self.host}:{self.port}")

            while True:
                client_socket, addr = server_socket.accept()
                logger.info(f"Connection from {addr}")
                self.handle_client(client_socket)

    def handle_client(self, client_socket: socket.socket):
        try:
            with client_socket:
                while True:
                    # First, receive the header to get the payload size
                    header_data = client_socket.recv(self.file_receiver.HEADER_SIZE)
                    if not header_data or len(header_data) < self.file_receiver.HEADER_SIZE:
                        break

                    encrypted_size = struct.unpack('<I', header_data[:4])[0]

                    # Now receive the payload
                    payload_data = client_socket.recv(encrypted_size)

                    # Combine header and payload
                    full_packet = header_data + payload_data

                    # Process the packet
                    file_complete = self.file_receiver.handle_file_packet(full_packet)

                    # Send response (you might want to customize this based on your protocol)
                    response = struct.pack('<I', 1 if file_complete else 0)
                    client_socket.send(response)

                    if file_complete:
                        break

        except Exception as e:
            logger.error(f"Error handling client: {e}")


def main():
    # This key should match the key used in the C++ client
    aes_key = b'0123456789abcdef'  # Replace with your actual key
    server = FileServer('0.0.0.0', 12345, aes_key)
    server.start()


if __name__ == "__main__":
    main()
