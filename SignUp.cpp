#include "SignUp.h"
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <sstream>

const std::string TRANSFER_FILE = "transfer.info";

SignUp::SignUp() : m_name(""), m_port(""), m_host(""), m_filePath("") {}

void SignUp::readTransferFile() {
    std::ifstream file(TRANSFER_FILE);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open transfer.info file");
    }

    std::string line;

    // Read the first line (host and port)
    if (std::getline(file, line)) {
        std::size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            m_host = line.substr(0, colonPos);          // Host before the colon
            m_port = line.substr(colonPos + 1);         // Port after the colon
        } else {
            throw std::runtime_error("Invalid format for host and port");
        }
    }

    // Read the second line (name)
    if (std::getline(file, line)) {
        m_name = line;  // Assign the full line to the name
    }

    // Read the third line (file path)
    if (std::getline(file, line)) {
        m_filePath = line;  // Assign the full line to the file path
    }

    file.close();


    // Validate that all required fields are present
    if (m_name.empty() || m_port.empty() || m_host.empty() || m_filePath.empty()) {
        throw std::runtime_error("Missing required information in transfer.info file");
    }
}

// Getter methods
std::string SignUp::getName() const {
    return m_name;
}

std::string SignUp::getPort() const {
    return m_port;
}

std::string SignUp::getHost() const {
    return m_host;
}

std::string SignUp::getFilePath() const {
    return m_filePath;
}