//
// Created by Ron on 14/10/2024.
//

#ifndef SIGNUP_H
#pragma once
#include <string>

class SignUp {
public:
    SignUp();
    void readTransferFile();
    std::string getName() const;
    std::string getPort() const;
    std::string getHost() const;
    std::string getFilePath() const;

private:
    std::string m_name;
    std::string m_port;
    std::string m_host;
    std::string m_filePath;
};
#define SIGNUP_H

#endif //SIGNUP_H
