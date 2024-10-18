from pathlib import Path
import logging
from enum import Enum

logger = logging.getLogger(__name__)
HOST = ''
DEFAULT_PORT = 1256
DEFAULT_PORT_FILE = "port.info"
PACKET_SIZE = 1024
SERVER_MAX_CONNECTIONS = 50
VERSION = 3
REQUEST_HEADER_SIZE = 23
MAX_REQUEST_SIZE = 1073741847  # 1GB payload + 23 bytes for header
AES_KEY_SIZE = 32
AES_BLOCK_SIZE = 16
CLIENT_ID_SIZE = 16
NAME_SIZE = 255
KEY_SIZE = 160

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

def readPort():
    port = DEFAULT_PORT
    port_file = Path(DEFAULT_PORT_FILE)
    if port_file.exists():
        try:
            port = int(port_file.read_text().strip())
            if not (0 <= port <= 65535):
                return DEFAULT_PORT
        except ValueError:
            return DEFAULT_PORT
    else:
        logger.warning("No port file found, using default port")
    return port
