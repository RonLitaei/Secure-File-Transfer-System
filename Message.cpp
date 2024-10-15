/*
 * Generates requests and responses.
 */
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

Response::Response() : Message() {}

Response::Response(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& payload)
    : Message(version, code, payload_size, payload) {}
