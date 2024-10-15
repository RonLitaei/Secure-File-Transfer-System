/*
 * Takes care of sign up
 */
#include "SignUp.h"
#include <fstream>
#include <stdexcept>
#include <iostream>

SignUp::SignUp() : _name(""), _port(""), _host(""), _filePath("") {}

void SignUp::readTransferFile() {
    std::ifstream file(TRANSFER_FILE);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open transfer.info file");
    }
    std::string line;
    if (std::getline(file, line)) {
        std::size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            _host = line.substr(0, colonPos);
            _port = line.substr(colonPos + 1);
        } else {
            throw std::runtime_error("Invalid format for host and port");
        }
    }
    if (std::getline(file, line)) {
        _name = line;
    }
    if (std::getline(file, line)) {
        _filePath = line;
    }
    file.close();
    if (_name.empty() || _port.empty() || _host.empty() || _filePath.empty()) {
        throw std::runtime_error("Missing required information in transfer.info file");
    }
}

std::string SignUp::getName() const { return _name; }
std::string SignUp::getPort() const { return _port; }
std::string SignUp::getHost() const { return _host; }
std::string SignUp::getFilePath() const { return _filePath; }