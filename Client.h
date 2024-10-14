#ifndef CLIENT_H
#define CLIENT_H

#pragma once
#include <boost/asio.hpp>
#include "Message.h"

class Client {
public:
    Client();
    void initialize();
    void authenticate();
    void connect(const std::string& host, const std::string& port);
    void send(const std::string& message);
    Response receive();
    void sendFile();
    static constexpr const char* ME_FILE = "info.me";
    static constexpr const char* PRIV_KEY_FILE = "priv.key";

private:
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket;
    boost::asio::ip::tcp::resolver resolver;
    bool connected = false;
    std::array<uint8_t, 16> client_id{};
    std::string client_name;
    std::string port;
    std::string host;
    std::string private_key;
    std::string decrypted_aes_key;
    std::string file_to_send;
    bool crc_valid = false;

    std::string readFromMeFile();
    void handleResponse(const Response& response);
    Request requestFromServer(RequestCodes code);
    void handleRegistrationSuccess(const Response& response);
    void handlePublicKeyReceived(const Response& response);
    void handleSignInSuccess(const Response& response);
    void handleSignInFailed();
    void handleFileReceived(const Response& response);
    std::string createPayload(RequestCodes code);
    // Helper methods
    void save_to_me_file(const std::array<uint8_t, 16>& uid, const std::string& name, const std::string& priv_key);
    void save_to_privkey_file(const std::string& priv_key);

    //friend class FileHandler;
};

#endif //CLIENT_H
