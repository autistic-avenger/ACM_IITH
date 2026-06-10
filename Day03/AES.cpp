// ============================================================
//  AES_Template.cpp
//  Undergraduate Cryptography Lab — AES-128 Template
//  Students must complete the TODO sections below.
//  All lookup tables and helper functions are provided.
// ============================================================

#include <iostream>
#include <vector>
#include <string>
#include <bitset>
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <algorithm>
#include <array>

// ============================================================
//  STATE TYPE DEFINITION
// ============================================================
// AES operates on a 4x4 byte matrix called the "State".
// state[row][col], rows 0-3, cols 0-3.
using State = std::array<std::array<uint8_t, 4>, 4>;

// ============================================================
//  LOOKUP TABLES  (do NOT modify)
// ============================================================

// AES S-box (Forward)
static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES Inverse S-box
static const uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Round constants for key expansion (indices 1–10 used)
static const uint8_t RCON[11] = {
    0x00,  // unused (index 0)
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36
};

// ============================================================
//  HELPER FUNCTIONS  (complete implementations provided)
// ============================================================

// Convert a hex string (e.g. "00112233...EEFF") to a byte vector
std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        uint8_t hi = 0, lo = 0;
        char ch = hex[i];
        char cl = hex[i + 1];
        if (ch >= '0' && ch <= '9')      hi = ch - '0';
        else if (ch >= 'A' && ch <= 'F') hi = ch - 'A' + 10;
        else if (ch >= 'a' && ch <= 'f') hi = ch - 'a' + 10;
        if (cl >= '0' && cl <= '9')      lo = cl - '0';
        else if (cl >= 'A' && cl <= 'F') lo = cl - 'A' + 10;
        else if (cl >= 'a' && cl <= 'f') lo = cl - 'a' + 10;
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return bytes;
}

// Convert a byte vector to an uppercase hex string
std::string bytesToHexString(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

// ============================================================
//  FUNCTION PROTOTYPES  (students implement the bodies below)
// ============================================================

std::vector<uint32_t> keyExpansion(const std::vector<uint8_t>& key);

void subBytes(State& state);
void shiftRows(State& state);
void mixColumns(State& state);
void addRoundKey(State& state,
                 const std::vector<uint32_t>& expandedKey,
                 int round);

std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& plaintext,
                                 const std::vector<uint8_t>& key);

std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& ciphertext,
                                 const std::vector<uint8_t>& key);

// ============================================================
//  STUDENT TODO SECTIONS
// ============================================================

// ------------------------------------------------------------
// AES-128 Key Expansion
// Input:  key — 16-byte (128-bit) key
// Output: vector of 44 32-bit words (expanded key schedule)
// ------------------------------------------------------------
std::vector<uint32_t> keyExpansion(const std::vector<uint8_t>& key) {
    // TODO:
    // AES-128 needs 11 round keys (44 words of 32 bits each).
    // The first 4 words come directly from the original key.
    //
    // Step 1: Load the first 4 words from key bytes:
    //   w[i] = (key[4i] << 24) | (key[4i+1] << 16) | (key[4i+2] << 8) | key[4i+3]
    //   for i = 0, 1, 2, 3
    //
    // Step 2: Generate words w[4] through w[43]:
    //   temp = w[i - 1]
    //   if (i % 4 == 0):
    //     RotWord(temp):  rotate left by one byte
    //       e.g. 0xAABBCCDD -> 0xBBCCDDAA
    //     SubWord(temp):  apply SBOX to each byte of temp
    //     temp = temp XOR Rcon[i / 4]
    //       Note: Rcon[j] is placed in the most significant byte only
    //       Rcon word = (RCON[j] << 24) | 0x000000
    //   w[i] = w[i - 4] XOR temp
    //
    // Return w (44 words)

    // Placeholder — replace with your implementation
    return std::vector<uint32_t>(44, 0x00000000);
}

// ------------------------------------------------------------
// SubBytes — apply AES S-box to every byte of the State
// ------------------------------------------------------------
void subBytes(State& state) {
    // TODO:
    // For each byte state[row][col] (row 0-3, col 0-3):
    //   state[row][col] = SBOX[ state[row][col] ]
    //
    // Hint: simply use state[row][col] as an index into the SBOX array.
}

// ------------------------------------------------------------
// ShiftRows — cyclically shift each row left
// ------------------------------------------------------------
void shiftRows(State& state) {
    // TODO:
    // Row 0: no shift         (shift left by 0)
    // Row 1: shift left by 1
    // Row 2: shift left by 2
    // Row 3: shift left by 3
    //
    // Example for row 1:
    //   [a, b, c, d] -> [b, c, d, a]
    //
    // Hint: use a temporary variable to hold bytes during rotation.
}

// ------------------------------------------------------------
// MixColumns — mix each column using GF(2^8) arithmetic
// ------------------------------------------------------------
void mixColumns(State& state) {
    // TODO:
    // For each column c (0 to 3), treat the 4 bytes as a polynomial
    // over GF(2^8) and multiply by the MixColumns matrix:
    //
    //  [2, 3, 1, 1]   [s0]
    //  [1, 2, 3, 1] x [s1]
    //  [1, 1, 2, 3]   [s2]
    //  [3, 1, 1, 2]   [s3]
    //
    // GF(2^8) multiplication rules (xtime = multiply by 2):
    //   xtime(a) = (a << 1) ^ (a & 0x80 ? 0x1b : 0x00)
    //   multiply by 2: use xtime
    //   multiply by 3: xtime(a) XOR a
    //
    // New column bytes:
    //   new_s0 = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3
    //   new_s1 = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3
    //   new_s2 = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3)
    //   new_s3 = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3)
}

// ------------------------------------------------------------
// AddRoundKey — XOR State with the round key words
// ------------------------------------------------------------
void addRoundKey(State& state,
                 const std::vector<uint32_t>& expandedKey,
                 int round) {
    // TODO:
    // The round key for round r consists of words:
    //   expandedKey[r*4], expandedKey[r*4+1], expandedKey[r*4+2], expandedKey[r*4+3]
    //
    // Each word covers one column of the State.
    // Word expandedKey[r*4 + col] maps to column col.
    //
    // Extract bytes from the word:
    //   byte 0 (MSB): (word >> 24) & 0xFF  -> state[0][col]
    //   byte 1:       (word >> 16) & 0xFF  -> state[1][col]
    //   byte 2:       (word >>  8) & 0xFF  -> state[2][col]
    //   byte 3 (LSB): (word      ) & 0xFF  -> state[3][col]
    //
    // XOR each state byte with the corresponding key byte.
}

// ------------------------------------------------------------
// AES-128 Encryption
// Input:  plaintext — 16 bytes
//         key       — 16 bytes
// Output: 16-byte ciphertext vector
// ------------------------------------------------------------
std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& plaintext,
                                 const std::vector<uint8_t>& key) {
    // TODO:
    //
    // Step 1: Key expansion
    //   auto expandedKey = keyExpansion(key);
    //
    // Step 2: Load plaintext into State (column-major order)
    //   state[row][col] = plaintext[col*4 + row]
    //
    // Step 3: Initial AddRoundKey (round 0)
    //   addRoundKey(state, expandedKey, 0);
    //
    // Step 4: Rounds 1 through 9 (standard rounds):
    //   subBytes(state);
    //   shiftRows(state);
    //   mixColumns(state);
    //   addRoundKey(state, expandedKey, round);
    //
    // Step 5: Final round 10 (NO MixColumns):
    //   subBytes(state);
    //   shiftRows(state);
    //   addRoundKey(state, expandedKey, 10);
    //
    // Step 6: Read ciphertext from State (column-major order)
    //   output[col*4 + row] = state[row][col]
    //
    // Return the 16-byte ciphertext vector

    // Placeholder — replace with your implementation
    return std::vector<uint8_t>(16, 0x00);
}

// ------------------------------------------------------------
// AES-128 Decryption
// Input:  ciphertext — 16 bytes
//         key        — 16 bytes
// Output: 16-byte plaintext vector
// ------------------------------------------------------------
std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& ciphertext,
                                 const std::vector<uint8_t>& key) {
    // TODO:
    //
    // Step 1: Key expansion (same expanded key as encryption)
    //   auto expandedKey = keyExpansion(key);
    //
    // Step 2: Load ciphertext into State (column-major order)
    //
    // Step 3: Initial AddRoundKey (round 10)
    //   addRoundKey(state, expandedKey, 10);
    //
    // Step 4: Rounds 9 down to 1 (inverse rounds):
    //   invShiftRows(state);     -- inverse of shiftRows (shift RIGHT)
    //   invSubBytes(state);      -- use INV_SBOX instead of SBOX
    //   addRoundKey(state, expandedKey, round);
    //   invMixColumns(state);    -- inverse mix columns
    //
    // Step 5: Final round 0:
    //   invShiftRows(state);
    //   invSubBytes(state);
    //   addRoundKey(state, expandedKey, 0);
    //
    // Helper for invShiftRows:
    //   Row 0: no shift
    //   Row 1: shift RIGHT by 1  (or left by 3)
    //   Row 2: shift RIGHT by 2  (or left by 2)
    //   Row 3: shift RIGHT by 3  (or left by 1)
    //
    // Helper for invMixColumns uses the inverse matrix:
    //  [14, 11, 13,  9]
    //  [ 9, 14, 11, 13]
    //  [13,  9, 14, 11]
    //  [11, 13,  9, 14]
    //
    // Use gmul(a, b) for GF(2^8) multiplication (see AES_Full.cpp).
    //
    // Step 6: Read plaintext from State (column-major)
    //
    // Return the 16-byte plaintext vector

    // Placeholder — replace with your implementation
    return std::vector<uint8_t>(16, 0x00);
}

// ============================================================
//  MAIN — sample driver (do not modify)
// ============================================================
int main() {
    std::string ptHex  = "00112233445566778899AABBCCDDEEFF";
    std::string keyHex = "000102030405060708090A0B0C0D0E0F";

    std::vector<uint8_t> plaintext = hexStringToBytes(ptHex);
    std::vector<uint8_t> key       = hexStringToBytes(keyHex);

    std::cout << "===== AES-128 Encryption/Decryption =====\n";
    std::cout << "Plaintext : " << ptHex  << "\n";
    std::cout << "Key       : " << keyHex << "\n";

    std::vector<uint8_t> ciphertext = aesEncrypt(plaintext, key);
    std::cout << "Ciphertext: " << bytesToHexString(ciphertext) << "\n";

    std::vector<uint8_t> recovered = aesDecrypt(ciphertext, key);
    std::cout << "Recovered : " << bytesToHexString(recovered) << "\n";

    return 0;
}