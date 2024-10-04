//
// Created by Ron on 09/09/2024.
//

#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <utility>
#include <fstream>
#include <iomanip>

#include "Base64Wrapper.h"
#include "RSAWrapper.h"

const uint8_t VERSION = 1;
const uint8_t HEADER_SIZE = 7;
//Positions in the buffer from the data that is being received
const uint8_t VERSION_POSITION = 0;
const uint8_t CODE_POSITION = 1;
const uint8_t PAYLOAD_SIZE_POSITION = 3;
const uint8_t PAYLOAD_POSITION = 7;

// Request Codes
enum class RequestCodes : uint16_t {
    REGISTRATION = 825,
    SENDING_PUBLIC_KEY = 826,
    SIGN_IN = 827,
    SENDING_FILE = 828,
    CRC_VALID = 900,
    CRC_NOT_VALID = 901,
    CRC_EXCEEDED_TRIES = 902
};

// Response Codes
enum class ResponseCodes : uint16_t {
    REGISTRATION_SUCCESS = 1600,
    REGISTRATION_FAILED = 1601,
    PUBLIC_KEY_RECEIVED_SENDING_AES = 1602,
    FILE_RECEIVED = 1603,
    MESSAGE_RECEIVED = 1604,
    SIGN_IN_SUCCESS = 1605,
    SIGN_IN_FAILED = 1606,
    GENERAL_ERROR = 1607
};

std::string TRANSFER_INFO_FILE_NAME = "transfer.info";
std::string USER_DATA_FILE_NAME = "transfer.info";
static constexpr const char* ME_FILE = "info.me";

void printAESKey(const std::string& aes_key) {
    // 1. Print as hex
    std::cout << "AES Key (hex): ";
    for (unsigned char c : aes_key) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(static_cast<unsigned char>(c));
    }
    std::cout << std::endl;

    // 2. Print as Base64
    Base64Wrapper base64;
    std::string encoded = base64.encode(aes_key);
    std::cout << "AES Key (Base64): " << encoded << std::endl;

    // Verification: decode and compare
    std::string decoded = base64.decode(encoded);
    if (decoded == aes_key) {
        std::cout << "Verification: Base64 encoding/decoding successful" << std::endl;
    } else {
        std::cout << "Verification: Base64 encoding/decoding mismatch!" << std::endl;
    }
}
// Method to read from me.info file
// this probably does not belong in this class
void read_from_me_file(std::array<uint8_t,16> uid, std::string& name, std::string& priv_key) {
    std::ifstream me_file(ME_FILE);
    if (!me_file.is_open()) {
        throw std::runtime_error("Could not open info.me for reading");
    }

    std::string uid_hex;
    std::getline(me_file, name);
    std::getline(me_file, uid_hex);
    std::getline(me_file, priv_key);

    // Convert hex string to uint8_t array
    if (uid_hex.size() < 32) { // Need 32 hex chars for 16 bytes
        throw std::runtime_error("UID hex string is too short");
    }

    for (size_t i = 0; i < uid.size(); i++) {
        std::string byte = uid_hex.substr(i * 2, 2);
        uid[i] = static_cast<uint8_t>(std::stoul(byte, nullptr, 16));
    }

    me_file.close();

    std::cout << "Client Name: " << name << std::endl;
    std::cout << "Unique ID: " << uid.data() << std::endl;
    std::cout << "Private Key: " << priv_key << std::endl;
}

// Method to save name, unique ID, and private key to me.info file
//this probably doesn't belong here too
void save_to_me_file(const std::array<uint8_t,16> uid,const std::string& name, const std::string& priv_key)  {
    std::ofstream me_file(ME_FILE);
    if (!me_file.is_open()) {
        throw std::runtime_error("Could not open info.me for writing");
    }
    // Convert UID to hex string
    std::stringstream hex_uid;
    hex_uid << std::hex << std::setfill('0');
    for (uint8_t byte : uid) {
        hex_uid << std::setw(2) << static_cast<int>(byte);
    }
    std::string priv_key_base64 = Base64Wrapper::encode(priv_key);
    me_file << name << std::endl;
    me_file << hex_uid.str() << std::endl;
    me_file << priv_key_base64 << std::endl;
    me_file.close();
}

// Check if me.info exists
static bool me_info_exists() {
    std::ifstream me_file(ME_FILE);
    return me_file.good();
}
class SignUp {
    static constexpr const char* TRANSFER_FILE = R"(C:\Users\Ron\Desktop\Defensive Programming\mmn15\Client 2.0\transfer.info)";


    static const size_t NAME_SIZE = 100;// or 255???
    std::string name;

    std::string host;
    std::string port;
    std::string file_path;

public:
    // Constructor
    SignUp() {
        try {
            read_transfer_file();
        }
        catch (const std::exception& e) {
            std::cout << "ERROR: Constructor for SignUp class failed: "<< e.what() << std::endl;
        }
    }

    // Method to read from transfer.info file
    void read_transfer_file() {
        std::ifstream transferFile(TRANSFER_FILE);
        if (!transferFile.is_open()) {
            throw std::runtime_error("Could not open transfer.info for reading");
        }
        std::string line;
        std::getline(transferFile, line);
        if (line.data()) {
            bool portRead = false;
            std::string tempHost;
            std::string tempPort;
            for(char i : line) {
                if((isdigit(i) || i == '.') && !portRead)
                    tempHost += i;
                if(i == ':') {
                    portRead = true;
                    continue;
                }
                if(isdigit(i) && portRead) {
                    tempPort += i;
                }
            }
            //TODO - add some sort of check to this crap name
            host = tempHost;
            port = tempPort;
        }
        //TODO - here too
        std::getline(transferFile,name);
        std::getline(transferFile, file_path);

        transferFile.close();

        std::cout << "HOST ADDRESS " << host << std::endl;
        std::cout << "PORT ADDRESS " << port << std::endl;
        std::cout << "Client Name: " << name << std::endl;
        std::cout << "File Path: " << file_path << std::endl;
    }

    std::string getName () {
        return name;
    }

    std::string getHost() {
        return host;
    }

    std::string getPort() {
        return port;
    }

    std::string getFilePath() {
        return file_path;
    }
};

class RsaKeys {
    std::unique_ptr<RSAPrivateWrapper> _privateKeyWrapper;
    std::string _publicKey;
    std::string _privateKey;
    std::string _base64EncodedPrivateKey;

public:
    // Constructor
    RsaKeys() : _privateKeyWrapper(std::make_unique<RSAPrivateWrapper>()) {
        _publicKey = _privateKeyWrapper->getPublicKey();
        _privateKey = _privateKeyWrapper->getPrivateKey();
        _base64EncodedPrivateKey = Base64Wrapper::encode(_privateKey);
    }

    // ... other methods ...

    // Update this method
    void setPrivateKeyFromBase64(const std::string& base64Key) {
        _base64EncodedPrivateKey = base64Key;
        _privateKey = Base64Wrapper::decode(base64Key);
        _privateKeyWrapper = std::make_unique<RSAPrivateWrapper>(_privateKey);
    }

    // Update other methods that use _privateKeyWrapper to use -> instead of .
    RSAPublicWrapper createEncryptor() const {
        return RSAPublicWrapper(_publicKey);
    }

    RSAPrivateWrapper createDecryptor() const {
        std::string decodedPrivateKey = Base64Wrapper::decode(_base64EncodedPrivateKey);
        return RSAPrivateWrapper(decodedPrivateKey);
    }

    std::string getPublicKey() const {
        return _publicKey;
    }

    std::string getPrivateKey() const {
        return _privateKey;
    }

    std::string getBase64EncodedPrivateKey() const {
        return _base64EncodedPrivateKey;
    }
};

class SendPublicKey {
    std::string client_name;
    std::string public_key;
public:
    SendPublicKey(std::string  name, std::string public_key) : client_name(std::move(name)),
    public_key(std::move(public_key)) {}

    explicit SendPublicKey(std::string clients_name) : client_name(std::move(clients_name)) {}

    std::string getClientName() {
        return client_name;
    }
    std::string getPublicKey() {
        return public_key;
    }
};

class LogIn {
    //name
};
class SendFile {
    //content size
    //original file size
    //packet number, total packets
    //file name
    //message content
};
class CrcValid {
    //file name
};
class CrcInvalid {
    //file name
};
class CrcTerminate {
    //file name
};

class Message {
protected:
    uint8_t version;
    uint16_t code;
    uint32_t payload_size;
    std::string payload;

public:

    // Default constructor
    Message() :
        version(0),
        code(0),
        payload_size(0),
        payload({}) {}

    // Parameterized constructor
    Message(const uint8_t version, const uint16_t code, const uint32_t payload_size, std::string payload) :
        version(version),
        code(code),
        payload_size(payload_size),
        payload(std::move(payload)) {}// Using move in case the payload is massive

    // Getters
    uint8_t getVersion() const { return version; }
    uint16_t getCode() const { return code; }
    uint32_t getPayloadSize() const { return payload_size; }
    std::string getPayload() const { return payload; }

    // Setters
    void setVersion(const uint8_t version) { this->version = version; }
    void setCode(const uint16_t code) { this->code = code; }
    void setPayloadSize(const uint32_t payload_size) { this->payload_size = payload_size; }
    void setPayload(const std::string& payload) { this->payload = payload; }

    // Display common message details
    virtual void display() const {
        std::cout << "Client ID: ";
        std::cout << "\nVersion: " << static_cast<int>(version) << "\n";
        std::cout << "Code: " << code << "\n";
        std::cout << "Payload Size: " << payload_size << "\n";
        std::cout << "Payload: " << payload << "\n";
    }

    virtual ~Message() = default;
};

// Request from the client to the server
class Request final : public Message {
private:
    std::array<uint8_t, 16> client_id;  // 16 bytes for client_id

public:
    // Default constructor
    Request() : client_id({}) {}

    // Parameterized constructor
    Request(const std::array<uint8_t, 16>& client_id, const uint8_t version, const uint16_t code,
        const uint32_t payload_size, const std::string& payload) :
        Message(version, code, payload_size, payload),
        client_id(client_id) {}

    // Getter for code
    std::array<uint8_t,16> getClientID() const { return client_id; }

    // Setter for code
    void setClientID(const std::array<uint8_t,16> client_id) { this->client_id = client_id; }

    // Display request details (override the base display)
    void display() const override {
        for (const char c : client_id) std::cout << c;
        std::cout << std::endl;
        Message::display();  // Call base class display

    }
};

// Response from the server to the client
class Response final : public Message {
private:
    bool status;

public:
    // Default constructor
    Response() : status(false) {}

    // Parameterized constructor
    Response(const uint8_t version, const uint16_t code, const uint32_t payload_size, const std::string& payload) :
        Message(version, code, payload_size, payload),
        status(true) {}

    // Getter for status
    uint16_t getStatus() const { return status; }

    // Setter for status
    void setStatus(const uint16_t status) { this->status = status; }

    // Display response details (override the base display)
    void display() const override {
        Message::display();  // Call base class display
        std::cout << "Status: " << status << "\n";
    }
};

class Handler {
    // Makes a request ready to be sent via the network
public:
    static std::string pack(const Request& request) {
        std::ostringstream oss;

        std::array<uint8_t, 16> client_id = request.getClientID();
        oss.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

        uint8_t version = request.getVersion();
        oss.write(reinterpret_cast<const char*>(&version), sizeof(version));

        uint16_t code = request.getCode();
        oss.write(reinterpret_cast<const char*>(&code), sizeof(code));

        uint32_t payload_size = request.getPayloadSize();
        oss.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));

        std::string payload = request.getPayload();
        oss.write(payload.data(), payload_size);
        //can use payload.size(), payload_size will be safer in the server side

        return oss.str();
    }

    // Unpacks data received via the network
    static Response unPackHeader(const std::vector<uint8_t>& data) {
        Response response;

        if (data.size() < HEADER_SIZE) { // 1 (version) + 2 (code) + 4 (payload_size) + at least 1 for payload
            throw std::runtime_error("Header size invalid. should be "+ std::to_string(HEADER_SIZE)
                + "bytes, received: " + std::to_string(data.size()));
        }

        // Deserialize the fields from big-endian byte order
        response.setVersion(data[VERSION_POSITION]);
        response.setCode((data[CODE_POSITION] << 8) | data[CODE_POSITION+1]);
        response.setPayloadSize((data[PAYLOAD_SIZE_POSITION] << 24) | (data[PAYLOAD_SIZE_POSITION+1] << 16)
            | (data[PAYLOAD_SIZE_POSITION+2] << 8) | data[PAYLOAD_SIZE_POSITION+3]);
        response.setStatus(true);

        return response;
    }

    static std::string unPackPayload(const std::vector<uint8_t>& data) {
        return std::string(data.begin(), data.end());
    }
};

class Client {
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket;
    boost::asio::ip::tcp::resolver resolver;
    int _max_length = 1024;

    void send(const std::string& message) {
        boost::asio::write(socket, boost::asio::buffer(message));
    }
    /*
     * usage:
     * while (true) {
            std::string response = receive();
            if (response.empty()) {
                break;
     */


public:
    Client() : socket(io_context), resolver(io_context) {}
    /*
     * Reads the header, extracts version, response code and payload size from it.
     * Using the payload size, extracts the actual payload.
     * Returns a Response object containing all the decoded information.
     */
    bool connected = false;
    std::array<uint8_t, 16> client_id{};
    std::string client_name;
    std::string port;
    std::string host;
    std::string private_key;
    std::string decrypted_aes_key;
    void handle_response(const Response& response) {
        ResponseCodes code = ResponseCodes(response.getCode());

        switch (code) {
            case ResponseCodes::REGISTRATION_SUCCESS: {
                for(size_t i =0; i < client_id.size(); i++) {
                    client_id[i] = response.getPayload()[i];
                }
            }
            break;
            case ResponseCodes::REGISTRATION_FAILED: {
                throw std::invalid_argument("Register failed, please try again with a different user name");
            }
            break;
            case ResponseCodes::PUBLIC_KEY_RECEIVED_SENDING_AES: {
                //save_to_me_file(client_id,client_name,private_key);//TODO - uncomment later
                std::string encrypted_aes_key;
                for(size_t i = client_id.size(); i < response.getPayloadSize(); i++) {
                    encrypted_aes_key += response.getPayload()[i];
                }
                RSAPrivateWrapper wrapper(private_key);
                decrypted_aes_key = wrapper.decrypt(encrypted_aes_key);
            }
            break;
            case ResponseCodes::SIGN_IN_SUCCESS:{}
            break;
            case ResponseCodes::SIGN_IN_FAILED:{}
            break;
            case ResponseCodes::FILE_RECEIVED:{}
            break;
            case ResponseCodes::MESSAGE_RECEIVED:{}
            break;
            case ResponseCodes::GENERAL_ERROR:{}
            break;
            default:
                throw std::invalid_argument("ERROR: Invalid response code");
        }

    }
    Response receive() {
        boost::asio::streambuf header_buffer;
        boost::system::error_code error;
        //Reads the header only
        boost::asio::read(socket, header_buffer.prepare(HEADER_SIZE), error);
        if (error) {
            throw boost::system::system_error(error);
            // TODO - add detailed error
        }
        header_buffer.commit(HEADER_SIZE);

        // Setting the vector
        boost::asio::const_buffer header_data = header_buffer.data();
        std::vector<uint8_t> header_vector(header_data.size());
        std::memcpy(header_vector.data(), header_data.data(), header_data.size());

        Response response = Handler::unPackHeader(header_vector);

        uint32_t payload_size = response.getPayloadSize();

        boost::asio::streambuf payload_buffer;
        payload_buffer.prepare(payload_size);

        // Reads the payload
        boost::asio::read(socket, payload_buffer.prepare(payload_size), error);
        if (error) {
            throw boost::system::system_error(error);
        }
        payload_buffer.commit(payload_size);

        // Updating vector with the payload
        boost::asio::const_buffer payload_data = payload_buffer.data();
        std::vector<uint8_t> payload_vector(payload_data.size());
        std::memcpy(payload_vector.data(), payload_data.data(), payload_data.size());

        // Updating the Response object with the payload
        response.setPayload(std::string(payload_vector.begin(), payload_vector.end()));

        std::cout << "Response data is: " << response.getPayload() << std::endl;

        return response;
    }

    void connect(const std::string& host, const std::string& port) {
        try {
            boost::asio::connect(socket, resolver.resolve(host, port));;
            std::cout << "Connection successful to " << host << ":" << port << std::endl;
        } catch (const boost::system::system_error& e) {
            std::cerr << "Connection failed: " << e.what() << std::endl;
        }
        connected = true;
    }
    bool isSocketReady() const {
        return socket.is_open();
    }


    // This will handle requests that will be sent to the server, the "code" stands for one
    // of the enum requests
    Request request_from_server(RequestCodes code) {
        try {
            std::string payload;
            switch (code) {
                case RequestCodes::REGISTRATION: {
                    SignUp s;
                    if (me_info_exists()){// Performing sign in
                        std::ifstream me_info("me.info");
                        if(!me_info.is_open()) {
                            throw std::invalid_argument("me.info not found");
                        }
                        code = RequestCodes::SIGN_IN;
                        std::getline(me_info, payload);//TODO - decide if to add a check to users name
                        me_info.close();
                    }
                    else {// Performing sign up
                        port = s.getPort();
                        host = s.getHost();
                        client_name = s.getName();
                        payload = s.getName();
                    }
                    payload.resize(255,'\0');
                }
                break;

                case RequestCodes::SENDING_PUBLIC_KEY: {
                    RsaKeys rsa = RsaKeys();
                    private_key = rsa.getPrivateKey();
                    std::string public_key = rsa.getPublicKey();
                    std::string name = client_name;

                    name.resize(255, '\0');
                    payload = name + public_key;
                    payload.resize(255 + 160, '\0');
                }
                break;

                case RequestCodes::SIGN_IN: {
                    payload = "Sign-in information";
                }// Add actual sign-in details
                break;

                case RequestCodes::SENDING_FILE: {
                    payload = "File data";  // Add actual file data
                }
                break;

                case RequestCodes::CRC_VALID: {
                    payload = "CRC validation success";  // Message for successful CRC validation
                }
                break;

                case RequestCodes::CRC_NOT_VALID: {
                    payload = "CRC validation failed";
                }// Message for failed CRC validation
                break;

                case RequestCodes::CRC_EXCEEDED_TRIES: {
                    payload = "Exceeded CRC retry attempts";
                }// Message for exceeding retry limit
                break;

                default:
                    throw std::invalid_argument("ERROR: Invalid request code");  // More specific error handling
            }

            // Create the request, serialize it, connect and send
            Request request(client_id, VERSION, static_cast<uint16_t>(code), static_cast<uint32_t>(payload.size()), payload);
            std::string packed_request = Handler::pack(request);
            if(!connected)
                connect(host, port);
            send(packed_request);
            return request;

        } catch (const std::invalid_argument& e) {
            std::cerr << "Invalid argument: " << e.what() << std::endl;  // Specific handling for invalid arguments
        } catch (const std::runtime_error& e) {
            std::cerr << "Runtime error: " << e.what() << std::endl;  // Handling for runtime errors
        } catch (const std::exception& e) {
            std::cerr << "Communication error: " << e.what() << std::endl;  // Generic handling for other exceptions
        }
        return Request();
    }
};

int main() {
    try {
        Client client;
        Request request = client.request_from_server(RequestCodes::REGISTRATION);
        Response response = client.receive();
        client.handle_response(response);
        std::cout << "Code: " << response.getCode() << std::endl;
        std::cout << "Payload size: " << response.getPayloadSize() << std::endl;
        std::cout << "Payload: " << response.getPayload() << std::endl;
        request = client.request_from_server(RequestCodes::SENDING_PUBLIC_KEY);
        response = client.receive();
        client.handle_response(response);
        std::cout << "Code: " << response.getCode() << std::endl;
        std::cout << "Payload size: " << response.getPayloadSize() << std::endl;
        std::cout << "Payload: " << response.getPayload() << std::endl;

    }
    catch (const std::invalid_argument& e) {
        std::cerr << "Invalid argument: " << e.what() << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }



    return 0;
}

