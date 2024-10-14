// File: Client.cpp
#include "Client.h"
#include "SignUp.h"
#include "FileHandler.h"
#include "Message.h"
#include "Handler.h"
#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include <stdexcept>
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <fstream>
#include <iomanip>
#include <filesystem>

uint8_t hex_to_byte(const std::string& hex) {
    return static_cast<uint8_t>(std::stoi(hex, nullptr, 16));
}

Client::Client()
    : socket(io_context), resolver(io_context), connected(false) {}

std::string Client::readFromMeFile() {
    std::ifstream me_info(ME_FILE);
    if(!me_info.is_open()) {
        throw std::invalid_argument("me.info not found");
    }
    std::ifstream priv_key_file(PRIV_KEY_FILE);
    if(!priv_key_file.is_open()) {
        throw std::invalid_argument("priv_key not found");
    }
    std::string client_name;
    std::getline(me_info, client_name);//TODO - decide if to add a check to users name
    std::string hex_string;
    std::getline(me_info, hex_string);
    std::string line;
    me_info.close();

    while(std::getline(priv_key_file, line)){//TODO - this needs to be read from priv.key
        if(line.empty())
            break;
        private_key += line;
    }
    priv_key_file.close();

    for (size_t i = 0; i < client_id.size(); ++i) {
        client_id[i] = hex_to_byte(hex_string.substr(i * 2, 2));
    }

    return client_name;
}
void Client::initialize() {
    SignUp signUp;
    signUp.readTransferFile();

    client_name = signUp.getName();
    port = signUp.getPort();
    host = signUp.getHost();
    file_to_send = signUp.getFilePath();

    if(std::filesystem::exists(ME_FILE)) {
        std::string name = readFromMeFile();
        if (client_name != name) {
            throw std::invalid_argument("Client name in file 'me.info' is not the same as in file 'transfer.info'");
        }
    }
}

void Client::authenticate() {
    try {
        // If me.info exists, try to sign in. If declined, the client will try to register with the same name
        if (!std::filesystem::exists(ME_FILE)) {
            Request request = requestFromServer(RequestCodes::REGISTRATION);
            Response response = receive();
            handleResponse(response);
            if (response.getCode() == static_cast<uint16_t>(ResponseCodes::REGISTRATION_SUCCESS)) {
                request = requestFromServer(RequestCodes::SENDING_PUBLIC_KEY);
                response = receive();
                handleResponse(response);
            }
        }
        else {
            Request request = requestFromServer(RequestCodes::SIGN_IN);
            Response response = receive();
            handleResponse(response);
            if (response.getCode() == static_cast<uint16_t>(ResponseCodes::SIGN_IN_FAILED)) {
                request = requestFromServer(RequestCodes::REGISTRATION);
                response = receive();
                handleResponse(response);
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Authentication failed: " << e.what() << std::endl;
    }
}

void Client::sendFile() {
    constexpr size_t MAX_ATTEMPTS = 4;
    for (size_t attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
        try {
            bool crc_valid = FileHandler::sendEncryptedFile(file_to_send, decrypted_aes_key, client_id, *this);

            if (crc_valid) {
                std::cout << "Client file: '" << file_to_send << "' saved successfully" << std::endl;
                requestFromServer(RequestCodes::CRC_VALID);
                receive(); // We don't need to handle this response
                return;
            }

            requestFromServer(RequestCodes::CRC_NOT_VALID);
        } catch (const std::exception& e) {
            std::cerr << "Error during file send attempt " << attempt + 1 << ": " << e.what() << std::endl;
        }
    }

    std::cout << "Client file: '" << file_to_send << "' corrupted (CRC failed)" << std::endl;
    requestFromServer(RequestCodes::CRC_EXCEEDED_TRIES);
    receive(); // We don't need to handle this response
}

void Client::connect(const std::string& host, const std::string& port) {
    try {
        boost::asio::connect(socket, resolver.resolve(host, port));
        std::cout << "Connection successful to " << host << ":" << port << std::endl;
        connected = true;
    } catch (const boost::system::system_error& e) {
        throw std::runtime_error("Connection failed: " + std::string(e.what()));
    }
}

void Client::send(const std::string& message) {
    boost::asio::write(socket, boost::asio::buffer(message));
}

Response Client::receive() {
    constexpr size_t HEADER_SIZE = 7;
    std::vector<uint8_t> header(HEADER_SIZE);

    boost::asio::read(socket, boost::asio::buffer(header));

    Response response = Handler::unPackHeader(header);

    std::vector<char> payload(response.getPayloadSize());
    boost::asio::read(socket, boost::asio::buffer(payload));

    response.setPayload(std::string(payload.begin(), payload.end()));

    return response;
}

void Client::handleResponse(const Response& response) {
    ResponseCodes code = static_cast<ResponseCodes>(response.getCode());

    switch (code) {
        case ResponseCodes::REGISTRATION_SUCCESS:
            handleRegistrationSuccess(response);
            break;
        case ResponseCodes::REGISTRATION_FAILED:
            throw std::runtime_error("Registration failed. Please try again with a different username.");
        case ResponseCodes::PUBLIC_KEY_RECEIVED_SENDING_AES:
            handlePublicKeyReceived(response);
            break;
        case ResponseCodes::SIGN_IN_SUCCESS:
            handleSignInSuccess(response);
            break;
        case ResponseCodes::SIGN_IN_FAILED:
            handleSignInFailed();
            break;
        case ResponseCodes::FILE_RECEIVED:
            handleFileReceived(response);
            break;
        case ResponseCodes::MESSAGE_RECEIVED:
            // Do nothing
            break;
        case ResponseCodes::GENERAL_ERROR:
            throw std::runtime_error("Server responded with a General error");
        default:
            throw std::runtime_error("Invalid response code: " + std::to_string(static_cast<int>(code)));
    }
}

Request Client::requestFromServer(RequestCodes code) {
    if (!connected) {
        connect(host, port);
    }

    std::string payload = createPayload(code);
    Request request(client_id, Message::VERSION, static_cast<uint16_t>(code), static_cast<uint32_t>(payload.size()), payload);
    std::string packed_request = Handler::pack(request);
    send(packed_request);
    return request;
}

// Private helper methods

void Client::handleRegistrationSuccess(const Response& response) {
    std::copy_n(response.getPayload().begin(), client_id.size(), client_id.begin());
}

void Client::handlePublicKeyReceived(const Response& response) {
    save_to_me_file(client_id, client_name, private_key);
    save_to_privkey_file(private_key);

    std::string encrypted_aes_key(response.getPayload().begin() + client_id.size(), response.getPayload().end());
    RSAPrivateWrapper wrapper(private_key);
    decrypted_aes_key = wrapper.decrypt(encrypted_aes_key);
}

void Client::handleSignInSuccess(const Response& response) {
    std::string encrypted_aes_key;
    for(size_t i = client_id.size(); i < response.getPayloadSize(); i++) {
        encrypted_aes_key += response.getPayload()[i];
    }
    RSAPrivateWrapper wrapper(Base64Wrapper::decode(private_key));
    decrypted_aes_key = wrapper.decrypt(encrypted_aes_key);
}

void Client::handleSignInFailed() {
    if (std::remove(ME_FILE) != 0 || std::remove(PRIV_KEY_FILE) != 0) {
        throw std::runtime_error("Failed to remove authentication files");
    }
}

void Client::handleFileReceived(const Response& response) {
    uint32_t crc = FileHandler::crcCalculator(file_to_send);
    uint32_t crc_from_server = *reinterpret_cast<const uint32_t*>(&response.getPayload()[275]);
    crc_valid = (crc == crc_from_server);
}

std::string Client::createPayload(RequestCodes code) {
    std::string payload;
    switch (code) {
        case RequestCodes::REGISTRATION:
        case RequestCodes::SIGN_IN:
            payload = client_name;
            payload.resize(255, '\0');
            break;
        case RequestCodes::SENDING_PUBLIC_KEY:
            {
                RSAPrivateWrapper rsa;
                private_key = rsa.getPrivateKey();
                std::string public_key = rsa.getPublicKey();
                payload = client_name;
                payload.resize(255, '\0');
                payload += public_key;
                payload.resize(255 + 160, '\0');
            }
            break;
        case RequestCodes::CRC_VALID:
        case RequestCodes::CRC_NOT_VALID:
        case RequestCodes::CRC_EXCEEDED_TRIES:
            payload = file_to_send;
            payload.resize(255, '\0');
            break;
        default:
            throw std::runtime_error("Invalid request code for payload creation");
    }
    return payload;
}

// Helper functions

void Client::save_to_me_file(const std::array<uint8_t, 16>& uid, const std::string& name, const std::string& priv_key) {
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

void Client::save_to_privkey_file(const std::string& priv_key) {
    std::ofstream priv_key_file(PRIV_KEY_FILE);
    if (!priv_key_file.is_open()) {
        throw std::runtime_error("Could not open private key file");
    }

    std::string priv_key_base64 = Base64Wrapper::encode(priv_key);
    priv_key_file << priv_key_base64 << std::endl;
    priv_key_file.close();
}