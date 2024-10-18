# mmn15
# Secure File Transfer System
A secure client-server application for encrypted file transfer using TCP/IP protocol.

## Overview
This system consists of two main components:
- Server (Python 3)
- Client (C++17)

The system enables secure file transfer between clients and the server using encryption (AES-CBC for symmetric encryption and RSA for asymmetric encryption).
The server stores each client's files in their own unique directory named after the client's uid.

### Server with a detailed logger:
![server](https://github.com/user-attachments/assets/798f333e-0025-4796-a24e-8acdae20d81b)

### The client side:
![client](https://github.com/user-attachments/assets/541a6935-8ce2-404b-bbda-7276ad80fc4e)


## Prerequisites

### Server Requirements
- At least python 3
- PyCryptodome library

### Client Requirements
- Crypto++ library
- Boost library

## Project Structure

### Server Files
- `port.info` - Contains the port number for the server
- Required directory structure:
  ```
  server/
  ├── server.py
  ├── port.info
  └── received_files/     # Directory for storing received files
  ```

### Client Files
- `transfer.info` - Contains connection details, user's name and file to transfer
- `me.info` - Contains client identification information
- Required directory structure:
  ```
  client/
  ├── client.exe
  ├── transfer.info
  ├── me.info	  # Generated after first registration
  └── priv.key    # Generated after first registration
  ```

## Configuration Files

### transfer.info format
```
127.0.0.1:1234
Username
path/to/file.txt/.docx/.mp3...etc
```

### me.info format (generated after registration)
```
Username
64f3f63985f04beb81a0e43321880182
MIGdMA0GCSqGSIb3DQEBA...
```

### priv.key format (generated after registration)
```
MIGdMA0GCSqGSIb3DQEBA...
```

### port.info format
```
1234
```

## Running the System

1. Start the Server:
   ```bash\cmd
   python main.py
   ```

2. Run the Client:
   ```bash\cmd
   Client.exe
   ```

The client will automatically:
1. Register if first time (or reconnect if previously registered)
2. Exchange encryption keys
3. Transfer the specified file securely
4. Verify file integrity using CRC

## Protocol Details

### Communication Flow
1. Client Registration
2. RSA Public Key Exchange
3. AES Key Exchange (encrypted with RSA)
4. File Transfer (encrypted with AES)
5. CRC Verification

### Error Handling
- The client will retry failed transfers up to 3 times
- After 3 failed attempts, the client will exit with a fatal error
- Connection errors are handled gracefully with appropriate error messages

## Security Features
- RSA 1024-bit asymmetric encryption for key exchange
- AES-CBC 256-bit symmetric encryption for file transfer
- CRC checksum verification
- Unique client identification using UUIDs
- Secure key storage

## Development Notes
- All numeric fields use little-endian representation
- Binary protocol over TCP
- The server supports multiple simultaneous clients using threading
- Protocol version: 3

## Troubleshooting
- Verify port availability before starting the server
- Ensure all configuration files are in the correct locations
- Check file permissions for read/write access
- Verify network connectivity between client and server

## Build Instructions

### Server
1. Install Python 3
2. Install required packages:
   ```bash\cmd
   pip install pycryptodome
   ```

### Client
1. Set C++17 standard
2. Configure Crypto++ library
3. Configure Boost library
3. Build the solution

## Notes
- Maximum supported user name length: 100 bytes
- Maximum supported file name length: 255 bytes
- Maximum supported file size: 800MB
- Files are transferred in chunks for better memory management
- Server keeps track of registered clients and their public keys
- All strings are null-terminated ASCII
- Default port is: 1256 (in case information in port.info is corrupted)
- At the moment, there is no database. All registered clients need to register again if the server restarts.
- If the client registers again after a server restart, their me.info and priv.key files will be deleted and replaced by new ones.
