#include <iostream>
#include "Client.h"

int main() {
    try {
        Client client;
        client.initialize();
        client.authenticate();
        client.sendFile();
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}