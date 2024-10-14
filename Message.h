#ifndef MESSAGE_H
#pragma once
#include <cstdint>
#include <string>
#include <array>
#include <vector>
#include <stdexcept>

enum class RequestCodes : uint16_t {
    REGISTRATION = 825,
    SENDING_PUBLIC_KEY = 826,
    SIGN_IN = 827,
    SENDING_FILE = 828,
    CRC_VALID = 900,
    CRC_NOT_VALID = 901,
    CRC_EXCEEDED_TRIES = 902
};

enum class ResponseCodes : uint16_t {
    REGISTRATION_SUCCESS = 1600,
    REGISTRATION_FAILED = 1601,
    PUBLIC_KEY_RECEIVED_SENDING_AES = 1602,
    FILE_RECEIVED = 1603,
    MESSAGE_RECEIVED = 1604,
    SIGN_IN_SUCCESS = 1605,
    SIGN_IN_FAILED = 1606,
    GENERAL_ERROR = 1607
};

class Message {
public:
    static constexpr uint8_t VERSION = 3;
    static constexpr uint8_t HEADER_SIZE = 7;

    Message();
    Message(uint8_t version, uint16_t code, uint32_t payload_size, std::string payload);

    uint8_t getVersion() const;
    uint16_t getCode() const;
    uint32_t getPayloadSize() const;
    const std::string getPayload() const;

    void setVersion(uint8_t version);
    void setCode(uint16_t code);
    void setPayloadSize(uint32_t payload_size);
    void setPayload(const std::string& payload);

    virtual std::vector<uint8_t> serialize() const = 0;
    virtual void deserialize(const std::vector<uint8_t>& data) = 0;

protected:
    uint8_t version;
    uint16_t code;
    uint32_t payload_size;
    std::string payload;
};

class Request : public Message {
public:
    Request();
    Request(const std::array<uint8_t, 16>& client_id, uint8_t version, uint16_t code,
            uint32_t payload_size, const std::string& payload);

    const std::array<uint8_t, 16>& getClientID() const;
    void setClientID(const std::array<uint8_t, 16>& client_id);

    std::vector<uint8_t> serialize() const override;
    void deserialize(const std::vector<uint8_t>& data) override;

private:
    std::array<uint8_t, 16> client_id;
};

class Response : public Message {
public:
    Response();
    Response(uint8_t version, uint16_t code, uint32_t payload_size, const std::string& payload);

    std::vector<uint8_t> serialize() const override;
    void deserialize(const std::vector<uint8_t>& data) override;
};

#define MESSAGE_H

#endif //MESSAGE_H
