#ifndef FILEHANDLER_H
#define FILEHANDLER_H
#pragma once
#include <string>
#include "Client.h"

namespace FileHandler {
    bool sendEncryptedFile(const std::string& filePath, const std::string& aesKey, const std::array<uint8_t, 16>&
        clientId, Client& client);

    uint32_t crcCalculator(const std::string &filePath);
}

#endif //FILEHANDLER_H
