#ifndef CRC_H
#define CRC_H

#include <cstdint>       // for uint_fast32_t
#include <cstddef>       // for size_t
#include <string>        // for std::string
#include <iostream>      // for std::cout, std::cerr
#include <fstream>       // for std::ifstream
#include <filesystem>    // for std::filesystem utilities

// CRC table definition
extern const uint_fast32_t crctab[8][256];

// Macro for unsigned 32-bit masking
#define UNSIGNED(n) ((n) & 0xffffffff)

// Function to compute CRC of memory block
unsigned long memcrc(char * b, size_t n);

// Function to read a file and compute its CRC
std::string readfile(const std::string& fname);

#endif // CRC_H
