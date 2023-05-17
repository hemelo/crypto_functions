//
// Created by Henrique on 16/05/2023.
//

#ifndef CRYPTO_FUNCTIONS_HASHINGUTILS_H
#define CRYPTO_FUNCTIONS_HASHINGUTILS_H

#include <string>
#include <vector>
#include "HashingUtils.h"
#include "ByteUtils.h"

namespace HashingUtils {


// Sigma0 function for SHA-256
    constexpr uint32_t sigma0(uint32_t x) {
        return ByteUtils::rotateRight(x, 2) ^ ByteUtils::rotateRight(x, 13) ^ ByteUtils::rotateRight(x, 22);
    }

// Sigma1 function for SHA-256
    constexpr uint32_t sigma1(uint32_t x) {
        return ByteUtils::rotateRight(x, 6) ^ ByteUtils::rotateRight(x, 11) ^ ByteUtils::rotateRight(x, 25);
    }

// Delta0 function for SHA-256
    constexpr uint32_t delta0(uint32_t x) {
        return ByteUtils::rotateRight(x, 7) ^ ByteUtils::rotateRight(x, 18) ^ (x >> 3);
    }

// Delta1 function for SHA-256
    constexpr uint32_t delta1(uint32_t x) {
        return ByteUtils::rotateRight(x, 17) ^ ByteUtils::rotateRight(x, 19) ^ (x >> 10);
    }

    std::vector<uint8_t> padInput(const std::string &input) {
        // Pre-processing: Pad the message
        std::vector<uint8_t> paddedInput(input.begin(), input.end());
        paddedInput.push_back(0x80);  // Append 1 bit after the message

        uint64_t messageLength = input.length() * 8;
        size_t paddedLength = paddedInput.size();
        while (paddedLength % 64 != 56) {
            paddedInput.push_back(0x00);  // Pad with zeros
            paddedLength = paddedInput.size();
        }

        // Append the message length in bits as a 64-bit big-endian integer
        paddedInput.push_back(static_cast<uint8_t>((messageLength >> 56) & 0xFF));
        paddedInput.push_back(static_cast<uint8_t>((messageLength >> 48) & 0xFF));
        paddedInput.push_back(static_cast<uint8_t>((messageLength >> 40) & 0xFF));
        paddedInput.push_back(static_cast<uint8_t>((messageLength >> 32) & 0xFF));
        paddedInput.push_back(static_cast<uint8_t>((messageLength >> 24) & 0xFF));
        paddedInput.push_back(static_cast<uint8_t>((messageLength >> 16) & 0xFF));
        paddedInput.push_back(static_cast<uint8_t>((messageLength >> 8) & 0xFF));
        paddedInput.push_back(static_cast<uint8_t>(messageLength & 0xFF));

        return paddedInput;
    }
}

#endif //CRYPTO_FUNCTIONS_HASHINGUTILS_H
