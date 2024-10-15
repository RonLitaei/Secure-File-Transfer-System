/*
 * Handles file reading, encryption, transmitting and crc.
 */
#include "FileHandler.h"
#include <fstream>
#include <vector>
#include <stdexcept>
#include <filesystem>
#include <algorithm>
#include <boost/endian/conversion.hpp>

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
    struct HeaderSizesData {// Sizes of each field
        uint8_t encrypted_data_size = 4;
        uint8_t file_size = 4;
        uint8_t packet_num_size = 2;
        uint8_t total_packets_size = 2;
    }sizes;

    uint32_t encryptedSize = static_cast<uint32_t>(encryptedContent.size());
    uint16_t totalPackets = static_cast<uint16_t>((encryptedSize + MAX_PAYLOAD_SIZE - 1) / MAX_PAYLOAD_SIZE);

    for (uint16_t packetNum = 0; packetNum < totalPackets; packetNum++) {
        size_t offset = packetNum * MAX_PAYLOAD_SIZE;
        size_t chunkSize = std::min(MAX_PAYLOAD_SIZE, encryptedContent.size() - offset);

        std::string payload;
        payload.reserve(HEADER_SIZE + chunkSize);

        // Append as little endian
        uint32_t le_encryptedSize = boost::endian::native_to_little(encryptedSize);
        uint32_t le_fileSize = boost::endian::native_to_little(fileSize);
        uint16_t le_packetNum = boost::endian::native_to_little(packetNum);
        uint16_t le_totalPackets = boost::endian::native_to_little(totalPackets);

        payload.append(reinterpret_cast<const char*>(&le_encryptedSize), sizes.encrypted_data_size);
        payload.append(reinterpret_cast<const char*>(&le_fileSize), sizes.file_size);
        payload.append(reinterpret_cast<const char*>(&le_packetNum), sizes.packet_num_size);
        payload.append(reinterpret_cast<const char*>(&le_totalPackets), sizes.total_packets_size);
        payload += filename;
        payload += encryptedContent.substr(offset, chunkSize);

        client.send(payload);
    }
}
/*
 * Encrypts the file, sends the first header and then sends each packet with its own meta-data.
 * Note: this method encrypts the entire file, this is done in order to be compatible with
 * the protocol, a better approach will be to encrypt each chunk, send it and redo.
 */
bool sendEncryptedFile(const std::string& filePath, const std::string& aesKey, const std::array<uint8_t, 16>& clientId, Client& client) {
    std::vector<char> fileContent = readFileContent(filePath);
    std::string encryptedContent = encryptContent(fileContent, aesKey);

    std::string filename = std::filesystem::path(filePath).filename().string();
    filename.resize(Client::NAME_PADDED_SIZE, '\0');

    sendInitialRequest(clientId, client);
    sendFilePackets(encryptedContent, static_cast<uint32_t>(fileContent.size()), filename, client);

    Response response = client.receive();
    if (response.getCode() != static_cast<uint16_t>(ResponseCodes::FILE_RECEIVED)) {
        throw std::runtime_error("Unexpected server response after file sending");
    }

    // Validate CRC
    uint16_t CRC_POS = 275;// CRC position in the payload
    std::string data = response.getPayload();
    uint32_t crc = crcCalculator(filePath);
    uint32_t crc_from_server = *reinterpret_cast<const uint32_t*>(&data[CRC_POS]);
    crc_from_server = boost::endian::little_to_native(crc_from_server);
    return (crc == crc_from_server);
}

} // namespace FileHandler