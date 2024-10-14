#include "handler.h"
#include <sstream>
#include <stdexcept>
#include <cstring>

std::string Handler::pack(const Request& request) {
    std::ostringstream oss;

    std::array<uint8_t, 16> client_id = request.getClientID();
    oss.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

    uint8_t version = request.getVersion();
    oss.write(reinterpret_cast<const char*>(&version), sizeof(version));

    uint16_t code = request.getCode();
    oss.write(reinterpret_cast<const char*>(&code), sizeof(code));

    uint32_t payload_size = request.getPayloadSize();
    oss.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));

    std::string payload = request.getPayload();
    oss.write(payload.data(), payload_size);

    return oss.str();
}

Response Handler::unPackHeader(const std::vector<uint8_t>& data) {
    Response response;

    if (data.size() < HEADER_SIZE) {
        throw std::runtime_error("Header size invalid...");
    }

    // Deserialize the fields from big-endian byte order
    uint8_t version = data[VERSION_POSITION];
    uint16_t code = (data[CODE_POSITION] << 8) | data[CODE_POSITION+1];
    uint32_t payload_size = (data[PAYLOAD_SIZE_POSITION] << 24)
        | (data[PAYLOAD_SIZE_POSITION+1] << 16)
        | (data[PAYLOAD_SIZE_POSITION+2] << 8)
        | data[PAYLOAD_SIZE_POSITION+3];

    response.setVersion(version);
    response.setCode(code);
    response.setPayloadSize(payload_size);
    //response.setStatus(true);

    return response;
}