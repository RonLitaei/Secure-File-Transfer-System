//
// Created by Ron on 09/09/2024.
//

#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <utility>
#include <fstream>

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

class SignUp {
    static constexpr const char* TRANSFER_FILE = R"(C:\Users\Ron\Desktop\Defensive Programming\mmn15\Client 2.0\transfer.info)";
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
    bool me_info_exists() {
        std::ifstream me_file(ME_FILE);
        return me_file.good();
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

    std::string getUniqueId() {
        return unique_id;
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
        std::istringstream stream(response_data, std::ios::binary);

        uint8_t version;
        stream.read(reinterpret_cast<char*>(&version), sizeof(version));

        uint16_t code;
        stream.read(reinterpret_cast<char*>(&code), sizeof(code));

        uint32_t payload_size;
        stream.read(reinterpret_cast<char*>(&payload_size), sizeof(payload_size));

        std::string payload;
        payload.resize(payload_size);  // Resize string to match payload size

        if (payload_size > 0) {
            stream.read(&payload[0], payload_size);  // Read the payload data
        }

        // Construct the Response object
        Response response(version, code, payload_size, payload);
        return response;
    }
    // Unpacks data received via the network
    static Response deserialize_header(const std::vector<uint8_t>& data) {
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

        Response response = Handler::deserialize_header(header_vector);

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
    }
    bool isSocketReady() const {
        return socket.is_open();
    }


    // This will handle requests that will be sent to the server, the "code" stands for one
    // of the enum requests
    void request_from_server(RequestCodes code) {
        try {
            std::string payload;
            std::array<char, 16> client_id{};//TODO - decide who the fuck am I
            std::string port;
            std::string host;
            switch (code) {
                case RequestCodes::REGISTRATION: {
                    SignUp s;
                    if (s.me_info_exists()){
                        payload = "Sign-in information";
                        break;
                    }
                    port = s.getPort();
                    host = s.getHost();
                    payload = s.getName();
                }
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

            // Create the request, serialize it, connect and send
            Request request(client_id, VERSION, static_cast<uint16_t>(code), static_cast<uint32_t>(payload.size()), payload);
            std::string serialized_request = Handler::serialize_request(request);
            connect(host, port);
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

    try {
        client.request_from_server(RequestCodes::REGISTRATION);
        while (true) {
            Response response = client.receive();
            if (!response.getStatus()) {
                break;
            }
            std::cout << "Code: " << response.getCode() << std::endl;
            std::cout << "Payload size: " << response.getPayloadSize() << std::endl;
            std::cout << "Payload: " << response.getPayload() << std::endl;


        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}

