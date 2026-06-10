// ============================================================
//  DES_Template.cpp
//  Undergraduate Cryptography Lab — DES Template
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
//  LOOKUP TABLES  (do NOT modify)
// ============================================================

// Initial Permutation (IP)
static const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

// Final Permutation (FP) — inverse of IP
static const int FP[64] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};

// Expansion table E (32 -> 48 bits)
static const int E[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

// Permutation P (32 bits)
static const int P[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
};

// PC-1 (64 -> 56 bits)
static const int PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

// PC-2 (56 -> 48 bits)
static const int PC2[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

// Left-shift schedule for key schedule
static const int SHIFT_TABLE[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
};

// All 8 DES S-boxes  [sbox][row 0-3][col 0-15]
static const int SBOX[8][4][16] = {
    // S1
    {
        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
    },
    // S2
    {
        {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
        {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
    },
    // S3
    {
        {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
        {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
        {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
        { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
    },
    // S4
    {
        { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
        {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
        {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
    },
    // S5
    {
        { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
        {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
        { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
        {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
    },
    // S6
    {
        {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
        {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
        { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
        { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
    },
    // S7
    {
        { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
        {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
        { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
        { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
    },
    // S8
    {
        {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
        { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
        { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
        { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
    }
};

// ============================================================
//  HELPER FUNCTIONS  (complete implementations provided)
// ============================================================

// Convert a hexadecimal string to a binary string
// e.g. "A" -> "1010"
std::string hexToBinary(const std::string& hex) {
    std::string binary;
    for (char c : hex) {
        int val = 0;
        if (c >= '0' && c <= '9')      val = c - '0';
        else if (c >= 'A' && c <= 'F') val = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') val = c - 'a' + 10;
        binary += std::bitset<4>(val).to_string();
    }
    return binary;
}

// Convert a binary string to a hexadecimal string
// e.g. "1010" -> "A"
std::string binaryToHex(const std::string& binary) {
    std::string hex;
    for (size_t i = 0; i + 4 <= binary.size(); i += 4) {
        std::bitset<4> bits(binary.substr(i, 4));
        int val = static_cast<int>(bits.to_ulong());
        std::ostringstream oss;
        oss << std::uppercase << std::hex << val;
        hex += oss.str();
    }
    return hex;
}

// Apply a permutation table to a binary string
// table entries are 1-indexed bit positions
std::string permute(const std::string& input, const int* table, int tableSize) {
    std::string output(tableSize, '0');
    for (int i = 0; i < tableSize; ++i) {
        output[i] = input[table[i] - 1];
    }
    return output;
}

// XOR two equal-length binary strings
std::string xorStrings(const std::string& a, const std::string& b) {
    std::string result(a.size(), '0');
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = ((a[i] - '0') ^ (b[i] - '0')) ? '1' : '0';
    }
    return result;
}

// Perform a left circular shift on a binary string by 'shifts' positions
std::string leftShift(const std::string& bits, int shifts) {
    return bits.substr(shifts) + bits.substr(0, shifts);
}

// ============================================================
//  FUNCTION PROTOTYPES  (students implement the bodies below)
// ============================================================

std::vector<std::string> generateRoundKeys(const std::string& key);

std::string feistelFunction(const std::string& rightHalf,
                             const std::string& roundKey);

std::string desEncrypt(const std::string& plaintext,
                       const std::string& key);

std::string desDecrypt(const std::string& ciphertext,
                       const std::string& key);

// ============================================================
//  STUDENT TODO SECTIONS
// ============================================================

// ------------------------------------------------------------
// Generate 16 round keys from the 64-bit DES key
// Input:  key — 16-character hex string (64 bits)
// Output: vector of 16 binary strings, each 48 bits long
// ------------------------------------------------------------
std::vector<std::string> generateRoundKeys(const std::string& key) {
    std::vector<std::string> roundKeys;

    // Convert hex key to 64-bit binary
    std::string keyBin = hexToBinary(key);

    // TODO:
    // 1. Apply PC-1 permutation to keyBin (64 bits -> 56 bits)
    //    Use: permute(keyBin, PC1, 56)
    std::string permutedKey = permute(keyBin,PC1,56);
    //
    // 2. Split the 56-bit result into two 28-bit halves C and D
    //    C = first 28 bits
    //    D = last  28 bits
    

    std::string C = permutedKey.substr(0, 28);

    std::string D = permutedKey.substr(28);
    // 3. For each of the 16 rounds:
    //    a. Left-shift C by SHIFT_TABLE[round] positions using leftShift()
    //    b. Left-shift D by SHIFT_TABLE[round] positions using leftShift()
    //    c. Concatenate C and D to form a 56-bit string CD
    //    d. Apply PC-2 permutation to CD (56 bits -> 48 bits)
    //       Use: permute(CD, PC2, 48)
    //    e. Append the result to roundKeys
    for (int round =0 ; round<16;++round){
        C = leftShift(C,SHIFT_TABLE[round]);
        D = leftShift(D,SHIFT_TABLE[round]);
        std::string CD = C+D;
        CD = permute(CD,PC2,48);
        roundKeys.push_back(CD);
    }
    
    //
    // 4. Return roundKeys (should contain exactly 16 strings of 48 bits each)
    return roundKeys;
}

// ------------------------------------------------------------
// Feistel (f) function
// Input:  rightHalf — 32-bit binary string
//         roundKey  — 48-bit binary string
// Output: 32-bit binary string
// ------------------------------------------------------------
std::string feistelFunction(const std::string& rightHalf,
                             const std::string& roundKey) {
    // TODO:
    // 1. Expansion permutation
    //    Expand rightHalf from 32 bits to 48 bits
    //    Use: permute(rightHalf, E, 48)
    std::string expanded_right = permute(rightHalf,E,48);
    // 2. XOR with round key
    //    XOR the 48-bit expanded block with roundKey
    //    Use: xorStrings(expanded, roundKey)
    std::string xoredStrs =  xorStrings(expanded_right,roundKey);
    // 3. S-box substitution
    //    Split the 48-bit XOR result into eight 6-bit groups
    //    For each group i (0..7):
    //      a. The row index   = first bit concatenated with last bit  (2 bits -> decimal 0-3)
    //      b. The column index = middle four bits (4 bits -> decimal 0-15)
    //      c. Look up SBOX[i][row][col]
    //      d. Convert the 4-bit result to a binary string
    //    Concatenate all eight 4-bit outputs -> 32-bit string
    std::string output;
    for (int i = 0; i < 8; ++i) {
        std::string block = xoredStrs.substr(i * 6, 6);
        int row_idx = (block[0] - '0') * 2 + (block[5] - '0');
        int col_idx = std::stoi(block.substr(1, 4), nullptr, 2);
        int sboxValue = SBOX[i][row_idx][col_idx];
        output += std::bitset<4>(sboxValue).to_string();
    }

    // 4. P permutation
    //    Apply permutation P to the 32-bit S-box output
    //    Use: permute(sboxOutput, P, 32)
    //
    std::string result = permute(output, P, 32);
    
    // Return the final 32-bit result
    return result;
}

// ------------------------------------------------------------
// DES Encryption
// Input:  plaintext — 16-character hex string (64 bits)
//         key       — 16-character hex string (64 bits)
// Output: 16-character hex string ciphertext
// ------------------------------------------------------------
std::string desEncrypt(const std::string& plaintext,
                       const std::string& key) {
    // TODO:
    // 1. Generate round keys
    //    Use: generateRoundKeys(key)
    std::vector<std::string> roundKeys = generateRoundKeys(key);
    // 2. Convert plaintext to 64-bit binary
    //    Use: hexToBinary(plaintext)
    std::string plaintedxtBin = hexToBinary(plaintext);
    // 3. Apply Initial Permutation (IP)
    //    Use: permute(plaintextBin, IP, 64)
    std::string initialIP = permute(plaintedxtBin,IP,64);

    // 4. Split the IP result into two 32-bit halves:
    //    L0 = first 32 bits
    //    R0 = last  32 bits
    std::string L0 = initialIP.substr(0,32);
    std::string R0 = initialIP.substr(32,64);
    
    std::vector<std::string> L ;
    L.push_back(L0);
    std::vector<std::string> R ;
    R.push_back(R0);
    // 5. Perform 16 Feistel rounds:
    //    For round i = 0 to 15:
    //      a. newL = R[i]
    //      b. newR = XOR( L[i], feistelFunction(R[i], roundKeys[i]) )
    //      c. L[i+1] = newL
    //      d. R[i+1] = newR
    for (int i = 0; i < 16; i++) {
        std::string newL = R[i];
        std::string newR = xorStrings(L[i],feistelFunction(R[i],roundKeys[i]));
        L.push_back(newL);
        R.push_back(newR);
    }
    // 6. Swap the final halves (concatenate R16 + L16)
    std::string combined = R[16] + L[16];
    // 7. Apply Final Permutation (FP)
    //    Use: permute(combined, FP, 64)
    std::string FinalP = permute(combined,FP,64);
    // 8. Convert binary result to hex
    //    Use: binaryToHex(result)
    std::string ans_hex_str =  binaryToHex(FinalP);
    // Return the hex ciphertext

    // Placeholder — replace with your implementation
    return ans_hex_str ;
}

// ------------------------------------------------------------
// DES Decryption
// Input:  ciphertext — 16-character hex string (64 bits)
//         key        — 16-character hex string (64 bits)
// Output: 16-character hex string (recovered plaintext)
// ------------------------------------------------------------
std::string desDecrypt(const std::string& ciphertext,
                       const std::string& key) {
    // TODO:
    // Decryption is identical to encryption EXCEPT:
    //   the round keys are applied in REVERSE order
    //   i.e. roundKeys[15] is used in round 1,
    //        roundKeys[0]  is used in round 16
    //
    // Steps:
    // 1. Generate round keys using generateRoundKeys(key)
    // 2. Reverse the round key vector (use std::reverse or index backwards)
    // 3. Follow the same steps as desEncrypt() using the reversed keys
    //
    // Return the hex plaintext

    // Placeholder — replace with your implementation
    return "0000000000000000";
}

// ============================================================
//  MAIN — sample driver (do not modify)
// ============================================================
int main() {
    std::string plaintext = "4E6F772069732074";
    std::string key       = "0123456789ABCDEF";

    std::cout << "===== DES Encryption/Decryption =====\n";
    std::cout << "Plaintext : " << plaintext << "\n";
    std::cout << "Key       : " << key       << "\n";

    std::string ciphertext = desEncrypt(plaintext, key);
    std::cout << "Ciphertext: " << ciphertext << "\n";

    // std::string recovered = desDecrypt(ciphertext, key);
    // std::cout << "Recovered : " << recovered  << "\n";

    return 0;
}