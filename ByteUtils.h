//
// Created by Henrique on 16/05/2023.
//

#ifndef CRYPTO_FUNCTIONS_BYTEUTILS_H
#define CRYPTO_FUNCTIONS_BYTEUTILS_H

namespace ByteUtils {
// Rotate right (circular right shift) operation
    constexpr uint32_t rotateRight(uint32_t value, int shift) {
        return (value >> shift) | (value << (32 - shift));
    }

// Rotate left (circular left shift) operation
    constexpr uint32_t rotateLeft(uint32_t value, int shift) {
        return (value << shift) | (value >> (32 - shift));
    }

// Ch function for SHA-256
    constexpr uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

// Maj function for SHA-256
    constexpr uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
}

#endif //CRYPTO_FUNCTIONS_BYTEUTILS_H
