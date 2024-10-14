#include "Message.h"
#include <algorithm>
#include <stdexcept>

Message::Message() : version(0), code(0), payload_size(0) {}

Message::Message(uint8_t version, uint16_t code, uint32_t payload_size, std::string payload)
    : version(version), code(code), payload_size(payload_size), payload(std::move(payload)) {}

uint8_t Message::getVersion() const { return version; }
uint16_t Message::getCode() const { return code; }
uint32_t Message::getPayloadSize() const { return payload_size; }
const std::string Message::getPayload() const { return payload; }

void Message::setVersion(uint8_t v) { version = v; }
void Message::setCode(uint16_t c) { code = c; }
void Message::setPayloadSize(uint32_t size) { payload_size = size; }
void Message::setPayload(const std::string& p) { 
    payload = p;
    payload_size = static_cast<uint32_t>(p.size());
}

Request::Request() : Message(), client_id({}) {}

Request::Request(const std::array<uint8_t, 16>& client_id, uint8_t version, uint16_t code,
                 uint32_t payload_size, const std::string& payload)
    : Message(version, code, payload_size, payload), client_id(client_id) {}

const std::array<uint8_t, 16>& Request::getClientID() const { return client_id; }
void Request::setClientID(const std::array<uint8_t, 16>& id) { client_id = id; }

std::vector<uint8_t> Request::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(client_id.size() + HEADER_SIZE + payload_size);
    
    data.insert(data.end(), client_id.begin(), client_id.end());
    data.push_back(version);
    data.push_back(static_cast<uint8_t>(code >> 8));
    data.push_back(static_cast<uint8_t>(code & 0xFF));
    for (int i = 3; i >= 0; --i) {
        data.push_back(static_cast<uint8_t>((payload_size >> (i * 8)) & 0xFF));
    }
    data.insert(data.end(), payload.begin(), payload.end());
    
    return data;
}

void Request::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < client_id.size() + HEADER_SIZE) {
        throw std::runtime_error("Insufficient data for Request deserialization");
    }
    
    std::copy_n(data.begin(), client_id.size(), client_id.begin());
    version = data[client_id.size()];
    code = (static_cast<uint16_t>(data[client_id.size() + 1]) << 8) | data[client_id.size() + 2];
    payload_size = (static_cast<uint32_t>(data[client_id.size() + 3]) << 24) |
                   (static_cast<uint32_t>(data[client_id.size() + 4]) << 16) |
                   (static_cast<uint32_t>(data[client_id.size() + 5]) << 8) |
                   data[client_id.size() + 6];
    
    if (data.size() < client_id.size() + HEADER_SIZE + payload_size) {
        throw std::runtime_error("Insufficient data for Request payload");
    }
    
    payload.assign(data.begin() + client_id.size() + HEADER_SIZE, 
                   data.begin() + client_id.size() + HEADER_SIZE + payload_size);
}

Response::Response() : Message() {}

Response::Response(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& payload)
    : Message(version, code, payload_size, payload) {}

std::vector<uint8_t> Response::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(HEADER_SIZE + payload_size);
    
    data.push_back(version);
    data.push_back(static_cast<uint8_t>(code >> 8));
    data.push_back(static_cast<uint8_t>(code & 0xFF));
    for (int i = 3; i >= 0; --i) {
        data.push_back(static_cast<uint8_t>((payload_size >> (i * 8)) & 0xFF));
    }
    data.insert(data.end(), payload.begin(), payload.end());
    
    return data;
}

void Response::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < HEADER_SIZE) {
        throw std::runtime_error("Insufficient data for Response deserialization");
    }
    
    version = data[0];
    code = (static_cast<uint16_t>(data[1]) << 8) | data[2];
    payload_size = (static_cast<uint32_t>(data[3]) << 24) |
                   (static_cast<uint32_t>(data[4]) << 16) |
                   (static_cast<uint32_t>(data[5]) << 8) |
                   data[6];
    
    if (data.size() < HEADER_SIZE + payload_size) {
        throw std::runtime_error("Insufficient data for Response payload");
    }
    
    payload.assign(data.begin() + HEADER_SIZE, data.begin() + HEADER_SIZE + payload_size);
}