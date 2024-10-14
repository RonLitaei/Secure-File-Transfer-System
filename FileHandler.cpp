#include "FileHandler.h"
#include <fstream>
#include <vector>
#include <stdexcept>
#include <filesystem>
#include <algorithm>
#include "AESWrapper.h"
#include "Handler.h"
#include "crc.h"


namespace FileHandler {

const size_t HEADER_SIZE = 267; // 4 + 4 + 2 + 2 + 255
const size_t PACKET_SIZE = 8192;
const size_t MAX_PAYLOAD_SIZE = PACKET_SIZE - HEADER_SIZE;

std::vector<char> readFileContent(const std::string& filePath) {
    std::filesystem::path absolutePath = std::filesystem::absolute(filePath);
    std::ifstream file(absolutePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + absolutePath.string());
    }

    file.seekg(0, std::ios::end);
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> fileContent(fileSize);
    if (!file.read(fileContent.data(), fileSize)) {
        throw std::runtime_error("Failed to read file content: " + absolutePath.string());
    }

    return fileContent;
}

uint32_t crcCalculator(const std::string &filePath) {
    std::vector<char> fileContent = readFileContent(filePath);
    return memcrc(fileContent.data(), static_cast<uint32_t>(fileContent.size()));
}

std::string encryptContent(std::vector<char>& content, const std::string& aesKey) {
    AESWrapper aesWrapper(reinterpret_cast<const unsigned char*>(aesKey.c_str()), aesKey.length());

    std::string encryptedContent = aesWrapper.encrypt(content.data(), content.size());
    uint32_t crc = memcrc(content.data(), content.size());
    encryptedContent.append(reinterpret_cast<const char*>(&crc), sizeof(crc));

    return encryptedContent;
}

void sendInitialRequest(const std::array<uint8_t, 16>& clientId, Client& client) {
    Request request(clientId, Message::VERSION, static_cast<uint16_t>(RequestCodes::SENDING_FILE), 0, "");
    std::string packed_request = Handler::pack(request);
    client.send(packed_request);
}

void sendFilePackets(const std::string& encryptedContent, uint32_t fileSize, const std::string& filename,
    Client& client) {
    uint32_t encryptedSize = static_cast<uint32_t>(encryptedContent.size());
    uint16_t totalPackets = static_cast<uint16_t>((encryptedSize + MAX_PAYLOAD_SIZE - 1) / MAX_PAYLOAD_SIZE);

    for (uint16_t packetNum = 0; packetNum < totalPackets; packetNum++) {
        size_t offset = packetNum * MAX_PAYLOAD_SIZE;
        size_t chunkSize = std::min(MAX_PAYLOAD_SIZE, encryptedContent.size() - offset);

        std::string payload;
        payload.reserve(HEADER_SIZE + chunkSize);

        payload.append(reinterpret_cast<const char*>(&encryptedSize), 4);
        payload.append(reinterpret_cast<const char*>(&fileSize), 4);
        payload.append(reinterpret_cast<const char*>(&packetNum), 2);
        payload.append(reinterpret_cast<const char*>(&totalPackets), 2);
        payload += filename;
        payload += encryptedContent.substr(offset, chunkSize);

        client.send(payload);
    }
}

bool sendEncryptedFile(const std::string& filePath, const std::string& aesKey, const std::array<uint8_t, 16>& clientId, Client& client) {
    std::vector<char> fileContent = readFileContent(filePath);
    std::string encryptedContent = encryptContent(fileContent, aesKey);

    std::string filename = std::filesystem::path(filePath).filename().string();
    filename.resize(255, '\0');

    sendInitialRequest(clientId, client);
    sendFilePackets(encryptedContent, static_cast<uint32_t>(fileContent.size()), filename, client);

    // Wait for server response
    Response response = client.receive();
    if (response.getCode() != static_cast<uint16_t>(ResponseCodes::FILE_RECEIVED)) {
        throw std::runtime_error("Unexpected server response after file send");
    }

    // Validate CRC
    std::string data = response.getPayload();
    uint32_t crc = crcCalculator(filePath);
    //uint32_t crc_from_server = *reinterpret_cast<const uint32_t*>(&response.getPayload()[275]);
    uint32_t crc_from_server = (data[275] << 24)
               | (data[275+1] << 16)
               | (data[275+2] << 8)
               | data[275+3];
    return (crc == crc_from_server);
}

} // namespace FileHandler