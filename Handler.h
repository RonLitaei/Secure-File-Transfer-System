#ifndef HANDLER_H
#define HANDLER_H

#include <string>
#include <vector>
#include <cstdint>
#include "Message.h"

const uint8_t SERVER_HEADER_SIZE = 7;
const uint8_t CLIENT_HEADER_SIZE = 23;
const uint8_t VERSION_POSITION = 0;
const uint8_t CODE_POSITION = 1;
const uint8_t PAYLOAD_SIZE_POSITION = 3;
const uint8_t PAYLOAD_POSITION = 7;

class Handler {
public:
    static std::string pack(const Request& request);
    static Response unPackHeader(const std::vector<uint8_t>& data);
};

#endif // HANDLER_H