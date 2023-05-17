#include "hashing.h"
#include "ByteUtils.h"
#include "HashingUtils.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <vector>

std::string readFileContent(const std::string &filePath) {
    std::ifstream file(filePath, std::ios::binary);

    if (!file) {
        std::cerr << "Error opening file: " << filePath << std::endl;
        return "";
    }

    std::ostringstream oss;
    char ch;

    while (file.get(ch)) {
        oss << ch;
    }

    return oss.str();
}

/**
 * @link https://blog.boot.dev/cryptography/how-sha-2-works-step-by-step-sha-256/
 * @param data
 * @return
 */
std::string Hashing::sha256(const std::string &data) {

    // Hard-coded constants that represent the first 32 bits of the fractional parts of the square roots of the first 8 primes
    uint32_t h0 = 0x6A09E667;
    uint32_t h1 = 0xBB67AE85;
    uint32_t h2 = 0x3C6EF372;
    uint32_t h3 = 0xA54FF53A;
    uint32_t h4 = 0x510E527F;
    uint32_t h5 = 0x9B05688C;
    uint32_t h6 = 0x1F83D9AB;
    uint32_t h7 = 0x5BE0CD19;

    // Each value (0-63) is the first 32 bits of the fractional parts of the cube roots of the first 64 primes (2 - 311).
    const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    std::vector<uint8_t> paddedInput = HashingUtils::padInput(data);

    for (size_t i = 0; i < paddedInput.size(); i += 64) {

        std::vector<uint32_t> w(64);

        for (int j = 0; j < 16; ++j) {
            w[j] = (paddedInput[i + j * 4] << 24) |
                   (paddedInput[i + j * 4 + 1] << 16) |
                   (paddedInput[i + j * 4 + 2] << 8) |
                   (paddedInput[i + j * 4 + 3
                   ]);
        }

        for (int j = 16; j < 64; ++j) {
            w[j] = HashingUtils::delta1(w[j - 2]) + w[j - 7] + HashingUtils::delta0(w[j - 15]) + w[j - 16];
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        // Main loop
        for (int j = 0; j < 64; ++j) {
            uint32_t t1 = h + HashingUtils::sigma1(e) + ByteUtils::ch(e, f, g) + k[j] + w[j];
            uint32_t t2 = HashingUtils::sigma0(a) + ByteUtils::maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    // Generate the final hash string
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::setw(8) << h0;
    oss << std::setw(8) << h1;
    oss << std::setw(8) << h2;
    oss << std::setw(8) << h3;
    oss << std::setw(8) << h4;
    oss << std::setw(8) << h5;
    oss << std::setw(8) << h6;
    oss << std::setw(8) << h7;

    return oss.str();
}

std::string Hashing::sha1(const std::string& data) {

    // Initialize hash values
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    // Pre-processing: Pad the message
    std::vector<uint8_t> paddedInput = HashingUtils::padInput(data);

    // Process the padded message in 512-bit (64-byte) chunks
    for (size_t i = 0; i < paddedInput.size(); i += 64) {
        std::vector<uint32_t> w(80);
        for (int j = 0; j < 16; ++j) {
            w[j] = (paddedInput[i + j * 4] << 24) |
                   (paddedInput[i + j * 4 + 1] << 16) |
                   (paddedInput[i + j * 4 + 2] << 8) |
                   (paddedInput[i + j * 4 + 3]);
        }

        for (int j = 16; j < 80; ++j) {
            w[j] = ByteUtils::rotateLeft(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        // Main loop
        for (int j = 0; j < 80; ++j) {
            uint32_t f, k;
            if (j < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (j < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (j < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = ByteUtils::rotateLeft(a, 5) + f + e + k + w[j];
            e = d;
            d = c;
            c = ByteUtils::rotateLeft(b, 30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    // Generate the final hash string
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::setw(8) << h0;
    oss << std::setw(8) << h1;
    oss << std::setw(8) << h2;
    oss << std::setw(8) << h3;
    oss << std::setw(8) << h4;

    return oss.str();
}

int main() {
    std::string input = "Hello, world!";

    std::cout << "Input: " << input << std::endl;
    std::cout << "SHA-1 Hash: " << Hashing::sha1(input) << std::endl;
    std::cout << "SHA-256 Hash: " << Hashing::sha256(input) << std::endl;

    return 0;
}