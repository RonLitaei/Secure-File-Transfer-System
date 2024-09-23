//
// Created by Ron on 09/09/2024.
//

#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <utility>
#include <fstream>

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
std::string USER_DATA_FILE_NAME = "me.info";

class SignUp {
    static constexpr const char* TRANSFER_FILE = "info.transfer";
    static constexpr const char* ME_FILE = "info.me";

    static const size_t NAME_SIZE = 100;// or 255???
    std::string name;

    std::string host;
    std::string port;
    std::string file_path;
    std::string unique_id;
    std::string private_key;

public:
    // Constructor
    SignUp() {
        try {
            if (!me_info_exists())
                read_transfer_file();
            else
                read_from_me_file();
        }
        catch (const std::exception& e) {
            std::cout << "ERROR: Constructor for SignUp class failed: "<< e.what() << std::endl;
        }
    }

    // Check if me.info exists
    static bool me_info_exists() {
        std::ifstream me_file(ME_FILE);
        return me_file.good();
    }

    // Method to read from transfer.info file
    void read_transfer_file() {
        std::ifstream transferFile(TRANSFER_FILE);
        if (!transferFile.is_open()) {
            throw std::runtime_error("Could not open info.transfer for reading");
        }
        std::string line;
        std::getline(transferFile, line);
        if (line.data()) {
            bool portRead = false;
            std::string tempHost;
            std::string tempPort;
            for(int i = 0; line[i] != '\n'; i++) {
                if((isdigit(line[i]) || line[i] == '.') && !portRead)
                    tempHost += line[i];
                if(line[i] == ':') {
                    portRead = true;
                    continue;
                }
                if(isdigit(line[i]) && portRead) {
                    tempPort += line[i];
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
    // Method to read from me.info file
    // this probably does not belong in this class
    void read_from_me_file() {
        std::ifstream me_file(ME_FILE);
        if (!me_file.is_open()) {
            throw std::runtime_error("Could not open info.me for reading");
        }

        std::getline(me_file, name);
        std::getline(me_file, unique_id);
        std::getline(me_file, private_key);

        me_file.close();

        std::cout << "Client Name: " << name << std::endl;
        std::cout << "Unique ID: " << unique_id << std::endl;
        std::cout << "Private Key: " << private_key << std::endl;
    }

    // Method to save name, unique ID, and private key to me.info file
    //this probably doesn't belong here too
    void save_to_me_file(const std::string& uid, const std::string& priv_key) const {
        std::ofstream me_file(ME_FILE);
        if (!me_file.is_open()) {
            throw std::runtime_error("Could not open info.me for writing");
        }

        me_file << name << std::endl;
        me_file << uid << std::endl;
        me_file << priv_key << std::endl;
        me_file.close();
    }
};

class SendPublicKey {
    //name
    //public key
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
    std::array<char, 16> client_id;  // 16 bytes for client_id

public:
    // Default constructor
    Request() : client_id({}) {}

    // Parameterized constructor
    Request(const std::array<char, 16>& client_id, const uint8_t version, const uint16_t code,
        const uint32_t payload_size, const std::string& payload) :
        Message(version, code, payload_size, payload),
        client_id(client_id) {}

    // Getter for code
    std::array<char,16> getClientID() const { return client_id; }

    // Setter for code
    void setClientID(const std::array<char,16> client_id) { this->client_id = client_id; }

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
    static std::string serialize_request(const Request& request) {
        std::ostringstream oss;

        std::array<char, 16> client_id = request.getClientID();
        oss.write(client_id.data(), client_id.size());

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

    static Response deserialize_response(const std::string& response_data) {
        std::istringstream stream(response_data);

        uint8_t version;
        stream.read(reinterpret_cast<char*>(&version), sizeof(version));

        uint16_t code;
        stream.read(reinterpret_cast<char*>(&code), sizeof(code));

        uint32_t payload_size;
        stream.read(reinterpret_cast<char*>(&payload_size), sizeof(payload_size));

        std::string payload(payload_size, '\0');
        stream.read(&payload[0], payload_size);

        Response response(version,code,payload_size,payload);
        return response;
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
    std::string receive() {
        std::vector<char> buffer(_max_length);
        size_t bytes_transferred = boost::asio::read(socket, boost::asio::buffer(buffer));
        return std::string(buffer.data(), bytes_transferred);
    }

public:
    Client() : socket(io_context), resolver(io_context) {}

    void connect(const std::string& host, const std::string& port) {
        try {
            boost::asio::connect(socket, resolver.resolve(host, port));;
            std::cout << "Connection successful to " << host << ":" << port << std::endl;
        } catch (const boost::system::system_error& e) {
            std::cerr << "Connection failed: " << e.what() << std::endl;
        }
    }
    bool isConnected() const {
        return socket.is_open();
    }


    // This will handle requests that will be sent to the server, the "code" stands for one
    // of the enum requests
    void handle_communication(RequestCodes code) {
        try {
            std::string payload;
            std::array<char, 16> client_id = {"WhoTheFuckAmI!?"};//TODO - decide who the fuck am I
            switch (code) {
                case RequestCodes::REGISTRATION:
                    payload = "Sign-up information";  // Add actual sign-up details
                break;

                case RequestCodes::SIGN_IN:
                    payload = "Sign-in information";  // Add actual sign-in details
                break;

                case RequestCodes::SENDING_PUBLIC_KEY:
                    payload = "Public key data";  // Add actual public key data
                break;

                case RequestCodes::SENDING_FILE:
                    payload = "File data";  // Add actual file data
                break;

                case RequestCodes::CRC_VALID:
                    payload = "CRC validation success";  // Message for successful CRC validation
                break;

                case RequestCodes::CRC_NOT_VALID:
                    payload = "CRC validation failed";  // Message for failed CRC validation
                break;

                case RequestCodes::CRC_EXCEEDED_TRIES:
                    payload = "Exceeded CRC retry attempts";  // Message for exceeding retry limit
                break;

                default:
                    throw std::invalid_argument("ERROR: Invalid request code");  // More specific error handling
            }

            // Create and send the request
            Request request(client_id, 1, static_cast<uint16_t>(code), static_cast<uint32_t>(payload.size()), payload);
            std::string serialized_request = Handler::serialize_request(request);
            send(serialized_request);

        } catch (const std::invalid_argument& e) {
            std::cerr << "Invalid argument: " << e.what() << std::endl;  // Specific handling for invalid arguments
        } catch (const std::runtime_error& e) {
            std::cerr << "Runtime error: " << e.what() << std::endl;  // Handling for runtime errors
        } catch (const std::exception& e) {
            std::cerr << "Communication error: " << e.what() << std::endl;  // Generic handling for other exceptions
        }
    }



};

int main() {
    Client client;
    client.connect("localhost", "1256");
    if (client.isConnected()) {
        client.handle_communication(RequestCodes::REGISTRATION);
        return 0;
    }
}
