/*
 * Packs and unpacks headers
 */
#include "handler.h"
#include <sstream>
#include <stdexcept>
#include <boost/endian/conversion.hpp>

std::string Handler::pack(const Request& request) {
    std::string packed;
    packed.reserve(CLIENT_HEADER_SIZE + request.getPayloadSize());

    packed.append(request.getClientID().begin(), request.getClientID().end());

    uint8_t version = request.getVersion();
    uint16_t code = boost::endian::native_to_little(request.getCode());
    uint32_t payloadSize = boost::endian::native_to_little(request.getPayloadSize());

    packed.append(reinterpret_cast<const char*>(&version), sizeof(version));
    packed.append(reinterpret_cast<const char*>(&code), sizeof(code));
    packed.append(reinterpret_cast<const char*>(&payloadSize), sizeof(payloadSize));
    packed.append(request.getPayload());

    return packed;
}

Response Handler::unPackHeader(const std::vector<uint8_t>& header) {
    Response response;

    if (header.size() < SERVER_HEADER_SIZE) {
        throw std::runtime_error("Header size invalid...");
    }

    uint8_t version = header[VERSION_POSITION];
    uint16_t code = *reinterpret_cast<const uint16_t*>(&header[CODE_POSITION]);
    uint32_t payloadSize = *reinterpret_cast<const uint32_t*>(&header[PAYLOAD_SIZE_POSITION]);

    code = boost::endian::little_to_native(code);
    payloadSize = boost::endian::little_to_native(payloadSize);

    response.setVersion(version);
    response.setCode(code);
    response.setPayloadSize(payloadSize);

    return response;
}