cmake_minimum_required(VERSION 3.29)
project(Client_2_0)
set(CMAKE_CXX_STANDARD 17)

# Specify the path to Boost
set(BOOST_ROOT "C:/Users/Ron/Desktop/boost_1_86_0")
set(BOOST_LIBRARYDIR "C:/Users/Ron/Desktop/boost_1_86_0/stage/lib")
# Add Crypto++ as a subproject
add_subdirectory("C:/Users/Ron/Desktop/Defensive Programming/cryptopp-master" cryptopp)
# Add Boost to the search path
set(CMAKE_PREFIX_PATH "${BOOST_ROOT}")

# Find Boost
find_package(Boost 1.86.0)

# Check if Boost was found
if(Boost_FOUND)
    message(STATUS "Found Boost ${Boost_VERSION}")
    include_directories(${Boost_INCLUDE_DIRS})
    link_directories(${Boost_LIBRARY_DIRS})
else()
    message(FATAL_ERROR "Boost not found")
endif()

# Define the executable
add_executable(Client_2_0
        RSAWrapper.cpp
        AESWrapper.cpp
        Base64Wrapper.cpp
        RSAWrapper.cpp
        crc.cpp
        crc.h
        Client.h
        main.cpp
        Handler.h
        Client.cpp
        SignUp.h
        Message.cpp
        FileHandler.cpp
        SignUp.cpp
        Handler.cpp
)

# Set compiler flags
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -pedantic -Werror)
endif()

# Define CRYPTOPP_ENABLE_NAMESPACE_WEAK=1
target_compile_definitions(${PROJECT_NAME} PRIVATE CRYPTOPP_ENABLE_NAMESPACE_WEAK=1)

# Link against Crypto++
target_link_libraries(${PROJECT_NAME} PRIVATE cryptopp)

# Include Crypto++ headers
target_include_directories(${PROJECT_NAME} PRIVATE
        "C:/Users/Ron/Desktop/Defensive Programming/cryptopp-master"
)

# If using MinGW, add these flags
if(MINGW)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
endif()
# Link Boost libraries to the executable
target_link_libraries(Client_2_0 ${Boost_LIBRARIES})
target_link_libraries(Client_2_0 PRIVATE ws2_32)
