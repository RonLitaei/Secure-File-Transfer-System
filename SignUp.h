//
// Created by Ron on 14/10/2024.
//

#ifndef SIGNUP_H
#pragma once
#include <string>
const std::string TRANSFER_FILE = "transfer.info";
class SignUp {
public:
    SignUp();
    void readTransferFile();
    std::string getName() const;
    std::string getPort() const;
    std::string getHost() const;
    std::string getFilePath() const;

private:
    std::string _name;
    std::string _port;
    std::string _host;
    std::string _filePath;
};
#define SIGNUP_H

#endif //SIGNUP_H
