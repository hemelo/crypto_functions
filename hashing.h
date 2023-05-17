#ifndef CRYPTO_FUNCTIONS_HASHING_H
#define CRYPTO_FUNCTIONS_HASHING_H


#include <string>

class Hashing {

public:
    static std::string sha1(const std::string& data);
    static std::string sha256(const std::string& data);
};

#endif //CRYPTO_FUNCTIONS_HASHING_H