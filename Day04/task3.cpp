/*
 * task3.cpp
 *
 * Task 3: Key Recovery Attack on 3-Round DES
 *         Matsui's Algorithm 2 — Linear Cryptanalysis
 *
 * ==========================================================
 * BACKGROUND
 * ==========================================================
 *
 * Matsui's Algorithm 2 recovers partial round-key bits by exploiting a
 * known linear approximation over the inner rounds of the cipher.
 *
 * For a 3-round DES with Feistel structure (no IP/FP, weak S-Boxes):
 *
 *   (P_L, P_R)  ─── round 1 ──►  ─── round 2 ──►  ─── round 3 ──►  (C_L, C_R)
 *
 * After expanding the Feistel recursion (rounds indexed 1..3):
 *
 *   Let A₁ = F(P_R,  K₁)          [round-1 function output]
 *   Let A₂ = F(P_L ⊕ A₁, K₂)     [round-2 function output]
 *   Let A₃ = F(P_R ⊕ A₂, K₃)     [round-3 function output]
 *
 *   C_L = P_L ⊕ A₁ ⊕ A₃
 *   C_R = P_R ⊕ A₂
 *
 * The 1-round linear approximation of round 1 (from Tasks 1 & 2):
 *
 *   Γ_P · P_R  ⊕  Γ_U · A₁  ≈  K₁_parity     (bias ε₁)
 *
 * Rewriting A₁ using the ciphertext (since C_L = P_L ⊕ A₁ ⊕ A₃):
 *
 *   A₁ = (C_L ⊕ P_L) ⊕ A₃
 *
 * Substituting into the approximation and rearranging:
 *
 *   [Γ_P · P_R  ⊕  Γ_U · P_L  ⊕  Γ_U · C_L]  ⊕  [Γ_U · A₃]  ≈  K₁_parity
 *    \___________ observable from PT/CT ___________/   \_ depends on K₃ _/
 *
 * This gives the attack strategy:
 *
 *   OBS(P, C) = parity(P_R, Γ_P) ⊕ parity(P_L, Γ_U) ⊕ parity(C_L, Γ_U)
 *
 *   For each candidate partial subkey K₃* (covering active S-Boxes of round 3):
 *     v = parity( F_partial(C_R, K₃*), Γ_U )
 *     test_bit = OBS(P, C) ⊕ v
 *
 *   Count(K₃*) = #{PT-CT pairs : test_bit = 0}
 *   Score(K₃*) = |Count(K₃*) - N/2|
 *
 *   Correct K₃*  → Score ≈ N · |ε₁|   (maximally biased)
 *   Wrong  K₃*   → Score ≈ 0          (unbiased noise)
 *
 * KEY INSIGHT — "Active S-Boxes" in round 3:
 *   Γ_U is a 32-bit mask on the output of F (after the P-permutation).
 *   Applying P⁻¹ to Γ_U gives a mask on the 32-bit S-Box output block.
 *   S-Box b (0..7) is "active" if any of its 4 output bits (positions
 *   [4b .. 4b+3]) are selected by this inverse-P mask.
 *   Only the 6 subkey bits feeding each active S-Box need to be guessed.
 *
 * ==========================================================
 * WHAT IS PRE-PROVIDED (infrastructure — do not modify)
 *   - All DES tables: SBOX, E_TABLE, P_TABLE, PC1, PC2, SHIFTS
 *   - generate_round_keys()  — derives K₁, K₂, K₃ from a 64-bit master key
 *   - round_function()       — F(R, K): E-expand → XOR K → S-Boxes → P-perm
 *   - encrypt_3round()       — 3-round Feistel encryption
 *   - generate_known_pairs() — creates N known (PT, CT) pairs
 *   - parity32()             — bitwise dot-product mod 2
 *   - extract_row/col()      — S-Box index decoding
 *   - print_recovered_key_bits() — verifies recovered bits against real key
 *
 * WHAT YOU MUST IMPLEMENT
 *   - FUNCTION 1: identify_active_sboxes
 *   - FUNCTION 2: partial_F_parity
 *   - FUNCTION 3: compute_observable
 *   - FUNCTION 4: key_recovery_attack
 *   - Complete:   main()
 *
 * Compile: g++ -O2 -std=c++17 -o task3 task3.cpp
 * Run:     ./task3
 * ==========================================================
 */

#include <iostream>
#include <vector>
#include <cstdint>
#include <cmath>
#include <cstdlib>
#include <algorithm>
#include <iomanip>
#include <string>

// ============================================================
// S-BOX DATA
// 8 custom "weak" S-Boxes (6-bit input → 4-bit output)
// Layout: SBOX[box_index][row][col]
//   row = 2-bit value from {input_bit5, input_bit0}  (outermost bits)
//   col = 4-bit value from {input_bit4 .. input_bit1} (inner bits)
// These are the same S-Boxes used in Tasks 1 and 2.
// ============================================================
static const int SBOX[8][4][16] = {
    {{14, 1, 6, 3, 8, 5, 7, 10, 13, 9, 15, 12, 2, 4, 11, 0},
     {15, 14, 2, 3, 4, 5, 7, 8, 6, 9, 0, 11, 12, 13, 1, 10},
     {15, 1, 5, 3, 7, 2, 8, 13, 4, 9, 6, 11, 14, 10, 12, 0},
     {4, 1, 5, 3, 8, 2, 6, 7, 10, 9, 15, 11, 12, 13, 14, 0}},
    {{4, 12, 10, 3, 5, 1, 6, 2, 8, 9, 14, 11, 0, 13, 7, 15},
     {12, 11, 9, 3, 14, 13, 6, 7, 8, 2, 10, 4, 0, 5, 1, 15},
     {5, 14, 2, 13, 6, 4, 11, 15, 12, 9, 3, 0, 1, 10, 8, 7},
     {1, 14, 2, 10, 7, 5, 6, 0, 8, 9, 12, 11, 4, 13, 3, 15}},
    {{14, 12, 6, 3, 4, 5, 2, 7, 8, 9, 15, 11, 0, 13, 1, 10},
     {0, 1, 2, 8, 13, 9, 10, 7, 3, 6, 12, 11, 4, 5, 14, 15},
     {4, 1, 5, 3, 13, 2, 11, 7, 15, 9, 12, 0, 6, 8, 14, 10},
     {0, 6, 2, 3, 7, 15, 10, 4, 13, 9, 1, 11, 14, 8, 12, 5}},
    {{12, 1, 0, 14, 4, 5, 6, 3, 10, 9, 2, 13, 8, 11, 7, 15},
     {0, 1, 2, 15, 4, 5, 8, 7, 9, 12, 10, 11, 3, 13, 14, 6},
     {3, 1, 2, 0, 9, 5, 11, 7, 6, 4, 13, 15, 14, 10, 12, 8},
     {0, 1, 9, 3, 4, 5, 2, 7, 11, 15, 10, 8, 13, 12, 6, 14}},
    {{14, 1, 7, 3, 8, 5, 6, 2, 4, 9, 10, 11, 0, 13, 12, 15},
     {2, 5, 14, 3, 9, 4, 11, 7, 8, 1, 13, 6, 15, 10, 0, 12},
     {0, 1, 5, 13, 7, 12, 10, 4, 3, 9, 2, 11, 14, 6, 8, 15},
     {12, 1, 6, 9, 2, 5, 3, 8, 13, 7, 14, 0, 4, 11, 10, 15}},
    {{0, 5, 2, 3, 8, 1, 6, 7, 4, 9, 15, 11, 12, 13, 14, 10},
     {0, 1, 14, 3, 4, 5, 11, 10, 12, 9, 7, 6, 8, 13, 2, 15},
     {12, 1, 2, 3, 4, 0, 11, 7, 6, 9, 15, 8, 5, 13, 14, 10},
     {6, 3, 2, 1, 4, 5, 10, 7, 8, 9, 14, 11, 15, 13, 0, 12}},
    {{2, 3, 1, 6, 5, 7, 4, 6, 9, 8, 11, 10, 13, 15, 14, 12},
     {1, 0, 2, 3, 5, 4, 7, 6, 10, 11, 8, 9, 15, 12, 13, 14},
     {1, 2, 3, 0, 4, 7, 5, 6, 8, 10, 9, 11, 12, 14, 15, 13},
     {2, 1, 0, 3, 5, 7, 6, 4, 8, 10, 13, 9, 13, 14, 12, 15}},
    {{12, 14, 7, 3, 9, 5, 6, 2, 10, 4, 8, 11, 1, 13, 0, 15},
     {0, 11, 7, 3, 15, 5, 6, 2, 8, 9, 10, 1, 12, 13, 14, 4},
     {0, 1, 9, 14, 4, 2, 10, 5, 13, 7, 15, 11, 12, 8, 3, 6},
     {0, 1, 2, 3, 7, 5, 6, 4, 14, 11, 13, 9, 8, 10, 12, 15}}};

// ============================================================
// DES TABLES  (all positions 0-indexed; bit 0 = MSB)
//
// Bit access convention throughout this file:
//   bit b (0 = MSB) of a uint32_t v  →  (v >> (31 - b)) & 1
//   bit b (0 = MSB) of a uint64_t v  →  (v >> (63 - b)) & 1
// ============================================================

// E-expansion: E_TABLE[i] = source bit position (0-indexed) in the 32-bit
// half-block that feeds position i of the 48-bit expanded output.
static const int E_TABLE[48] = {
    31, 0, 1, 2, 3, 4,      // input to S-Box 0
    3, 4, 5, 6, 7, 8,       // input to S-Box 1
    7, 8, 9, 10, 11, 12,    // input to S-Box 2
    11, 12, 13, 14, 15, 16, // input to S-Box 3
    15, 16, 17, 18, 19, 20, // input to S-Box 4
    19, 20, 21, 22, 23, 24, // input to S-Box 5
    23, 24, 25, 26, 27, 28, // input to S-Box 6
    27, 28, 29, 30, 31, 0   // input to S-Box 7
};

// P-permutation: P_TABLE[i] = source bit position (0-indexed) in the
// 32-bit S-Box output block that maps to output position i.
static const int P_TABLE[32] = {
    15, 6, 19, 20, 28, 11, 27, 16,
    0, 14, 22, 25, 4, 17, 30, 9,
    1, 7, 23, 13, 31, 26, 2, 8,
    18, 12, 29, 5, 21, 10, 3, 24};

// DES key schedule tables.
// PC1[i]  = source bit position (0-indexed) in the 64-bit master key
//           that maps to position i of the 56-bit key.
// PC2[i]  = source bit position (0-indexed) within the 56-bit C||D state
//           that maps to position i of the 48-bit round subkey.
// SHIFTS  = number of left-circular-rotations of the 28-bit C and D
//           halves before extracting each round's subkey.
static const int PC1[56] = {
    56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
    9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
    13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3};
static const int PC2[48] = {
    13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
    22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31};
static const int SHIFTS[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// ============================================================
// HELPER UTILITIES (pre-provided)
// ============================================================

// parity32: dot product (inner product mod 2) of a 32-bit value
// with a 32-bit mask.  Returns 0 or 1.
// In linear cryptanalysis notation: "mask · value" means the XOR
// of all bits in (value AND mask).
int parity32(uint32_t value, uint32_t mask)
{
    uint32_t x = value & mask;
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return x & 1;
}

// extract_row: decode the 2-bit row index from a 6-bit S-Box input.
// DES rule: row = { bit5 (outermost), bit0 (innermost) }.
int extract_row(int in6)
{
    // import your logic from task1
}

// extract_col: decode the 4-bit column index from a 6-bit S-Box input.
// DES rule: col = bits 4..1 (the inner 4 bits).
int extract_col(int in6)
{
    // import your logic from task1
}

// ============================================================
// PRE-PROVIDED: generate_round_keys
//
// Derives num_rounds 48-bit DES round subkeys from a 64-bit
// master key using the standard key schedule: PC-1 → left
// circular shifts → PC-2.
//
// Parameters:
//   master_key — 64-bit key (bit 0 = MSB)
//   num_rounds — number of subkeys to generate (default 3)
// Returns:
//   vector of num_rounds uint64_t values, each holding a 48-bit
//   subkey in its low 48 bits.
// ============================================================
std::vector<uint64_t> generate_round_keys(uint64_t master_key, int num_rounds = 3)
{
    uint64_t key56 = 0;
    for (int i = 0; i < 56; i++)
    {
        int bit = (master_key >> (63 - PC1[i])) & 1;
        key56 |= ((uint64_t)bit << (55 - i));
    }
    uint32_t C = (uint32_t)((key56 >> 28) & 0x0FFFFFFF);
    uint32_t D = (uint32_t)(key56 & 0x0FFFFFFF);

    std::vector<uint64_t> round_keys;
    for (int r = 0; r < num_rounds; r++)
    {
        int s = SHIFTS[r];
        C = ((C << s) | (C >> (28 - s))) & 0x0FFFFFFF;
        D = ((D << s) | (D >> (28 - s))) & 0x0FFFFFFF;
        uint64_t CD = ((uint64_t)C << 28) | D;
        uint64_t rk = 0;
        for (int i = 0; i < 48; i++)
        {
            int bit = (CD >> (55 - PC2[i])) & 1;
            rk |= ((uint64_t)bit << (47 - i));
        }
        round_keys.push_back(rk);
    }
    return round_keys;
}

// ============================================================
// PRE-PROVIDED: round_function
//
// Computes F(R, K): the DES round function.
//   Input  R — 32-bit right half of the Feistel state
//   Input  K — 48-bit round subkey (stored in low 48 bits)
//   Output   — 32-bit result
//
// Pipeline:  E-expansion (32→48)  →  XOR with K  →
//            8 S-Boxes (6→4 bits each)  →  P-permutation (32→32)
// ============================================================
uint32_t round_function(uint32_t R, uint64_t K)
{
    uint64_t expanded = 0;
    for (int i = 0; i < 48; i++)
    {
        int bit = (R >> (31 - E_TABLE[i])) & 1;
        expanded |= ((uint64_t)bit << (47 - i));
    }
    expanded ^= K;

    uint32_t sbox_out = 0;
    for (int b = 0; b < 8; b++)
    {
        int in6 = (int)((expanded >> (42 - 6 * b)) & 0x3F);
        int out4 = SBOX[b][extract_row(in6)][extract_col(in6)];
        sbox_out |= (uint32_t)(out4 << (28 - 4 * b));
    }

    uint32_t result = 0;
    for (int i = 0; i < 32; i++)
    {
        int bit = (sbox_out >> (31 - P_TABLE[i])) & 1;
        result |= (uint32_t)(bit << (31 - i));
    }
    return result;
}

// ============================================================
// PRE-PROVIDED: encrypt_3round
//
// 3-round Feistel encryption (no initial / final permutation).
//
// Feistel convention used here:
//   - Rounds 1 and 2 end with a half-swap.
//   - Round 3 does NOT swap (output is taken directly).
//
// Resulting ciphertext halves (derivable from the Feistel equations):
//   C_L = P_L ⊕ A₁ ⊕ A₃
//   C_R = P_R ⊕ A₂
// where A_i = F(input_to_round_i, K_i).
//
// Parameters:
//   P_L, P_R   — 32-bit left and right plaintext halves
//   round_keys — 3-element vector from generate_round_keys()
// Returns:
//   std::pair (C_L, C_R)
// ============================================================
std::pair<uint32_t, uint32_t> encrypt_3round(uint32_t P_L, uint32_t P_R,
                                             const std::vector<uint64_t> &round_keys)
{
    uint32_t left = P_L, right = P_R;
    for (int r = 0; r < 3; r++)
    {
        left ^= round_function(right, round_keys[r]);
        if (r < 2)
            std::swap(left, right);
    }
    return {left, right};
}

// ============================================================
// PRE-PROVIDED: generate_known_pairs
//
// Generates N random known-plaintext / ciphertext pairs under
// the given 64-bit master key using 3-round DES.
//
// Each pair is returned as a pair of uint64_t values:
//   plaintext  = (P_L << 32) | P_R
//   ciphertext = (C_L << 32) | C_R
// ============================================================
std::vector<std::pair<uint64_t, uint64_t>>
generate_known_pairs(uint64_t master_key, int N)
{
    auto rkeys = generate_round_keys(master_key, 3);
    std::vector<std::pair<uint64_t, uint64_t>> pairs;
    pairs.reserve(N);
    for (int i = 0; i < N; i++)
    {
        uint32_t P_L = (uint32_t)rand();
        uint32_t P_R = (uint32_t)rand();
        auto [C_L, C_R] = encrypt_3round(P_L, P_R, rkeys);
        pairs.push_back({((uint64_t)P_L << 32) | P_R,
                         ((uint64_t)C_L << 32) | C_R});
    }
    return pairs;
}

// ============================================================
// LINEAR TRAIL PARAMETERS  (substitute your Task 2 values below)
//
// GAMMA_P : 32-bit mask on P_R — the right-half input to round 1.
//           Derived from the best S-Box's alpha mask (6 bits) by
//           tracing each set bit of alpha back through E_TABLE to
//           the corresponding bit position in P_R.
//
// GAMMA_U : 32-bit mask on A₁ = F(P_R, K₁) — the output of round 1.
//           Derived from the best S-Box's beta mask (4 bits) by
//           finding where each set bit of beta ends up after the
//           P-permutation (i.e., which P output positions correspond
//           to the chosen S-Box output bits).
//
// EPSILON : Linear bias ε₁ = LAT[BEST_ALPHA][BEST_BETA] / 64.0
//           (the signed bias of the best 1-round approximation).
//
// *** REPLACE THE ZERO PLACEHOLDERS WITH YOUR TASK 2 VALUES ***
// ============================================================
static const int BEST_SBOX = 0;             // TODO: 0-indexed S-Box number
static const int BEST_ALPHA = 0;            // TODO: 6-bit input  mask from Task 2
static const int BEST_BETA = 0;             // TODO: 4-bit output mask from Task 2
static const uint32_t GAMMA_P = 0x00000000; // TODO: 32-bit plaintext-side mask
static const uint32_t GAMMA_U = 0x00000000; // TODO: 32-bit output-side mask
static const double EPSILON = 0.0;          // TODO: signed bias ε₁

// ============================================================
// FUNCTION 1:  identify_active_sboxes
//
// Determine which S-Boxes in the last round (round 3) are
// "active" — i.e., their output bits are selected by GAMMA_U
// after passing through the P-permutation.
//
// Input:
//   gamma_u — 32-bit mask on the round function output (after P)
//
// Output:
//   A vector of active S-Box indices (0-indexed), sorted ascending.
//   Example: if only S-Box 4 is active, return {4}.
//
// Algorithm (pseudocode):
//
//   1. Compute the inverse-P mask:
//      Initialise inv_P_mask = 0.
//      For each bit position i from 0 to 31:
//        If bit i is set in gamma_u:
//          Look up src = P_TABLE[i]  (the S-Box output position that
//          feeds P output position i).
//          Set bit src in inv_P_mask.
//      Now inv_P_mask identifies which S-Box output positions
//      contribute to GAMMA_U.
//
//   2. Identify active S-Boxes:
//      S-Box b (0..7) owns bit positions 4*b through 4*b+3 of the
//      32-bit S-Box output block.
//      For each b from 0 to 7:
//        If any of the bits at positions 4*b .. 4*b+3 is set in
//        inv_P_mask, then S-Box b is active — add b to the result.
// ============================================================
std::vector<int> identify_active_sboxes(uint32_t gamma_u)
{

    // TODO: Implement the two-step algorithm described above.
    // Your implementation should populate and return the 'active' vector.

    std::vector<int> active;
    return active; // placeholder
}

// ============================================================
// FUNCTION 2:  partial_F_parity
//
// Partially evaluate the round-3 function F(C_R, K₃) using only
// the active S-Boxes, then return the 1-bit dot-product parity of
// the partial output with GAMMA_U.
//
// Why partial?
//   We only guess the 6-bit subkey slice for each active S-Box.
//   Non-active S-Boxes have no bits set in inv_P_mask, so their
//   outputs do not affect parity(result, GAMMA_U) — their unknown
//   key bits are irrelevant.
//
// Input:
//   R           — 32-bit value C_R (right half of ciphertext)
//   k3_partial  — candidate partial subkey packed MSB-first:
//                 bits for active[0] occupy the highest 6 bits,
//                 bits for active[1] occupy the next 6 bits, etc.
//                 Total width = 6 * active.size() bits.
//   active      — vector of active S-Box indices (from Function 1)
//   gamma_u     — 32-bit output mask GAMMA_U
//
// Output:
//   A single bit (0 or 1): parity( F_partial(C_R, K₃*), gamma_u )
//
// Algorithm (pseudocode):
//
//   Step 1 — E-expand R into a 48-bit block.
//            (This step is pre-implemented for you below.)
//
//   Step 2 — For each active S-Box (iterate over the 'active' vector
//            with a running index idx = 0, 1, ...):
//
//     a. Extract the 6-bit slice of the 48-bit expanded block that
//        feeds S-Box b.  S-Box b uses bits at positions 6*b through
//        6*b+5 of the 48-bit block.
//
//     b. Extract the 6 candidate key bits for S-Box b from k3_partial.
//        The bits for active[0] are packed in the highest 6 positions,
//        active[1] in the next 6, and so on.
//
//     c. XOR the expanded bits (step a) with the key bits (step b)
//        to form the 6-bit S-Box input.
//
//     d. Look up the 4-bit S-Box output using extract_row() and
//        extract_col() on the 6-bit input, then index SBOX[b].
//
//     e. Place the 4-bit result into a 32-bit sbox_output word at
//        bit positions 4*b through 4*b+3.
//        (Non-active S-Boxes contribute 0 — leave their bits as 0.)
//
//   Step 3 — Apply the P-permutation to sbox_output to get the
//            partial round function output.
//            Use P_TABLE in the same way as round_function().
//
//   Step 4 — Return parity32(partial_output, gamma_u).
// ============================================================
int partial_F_parity(uint32_t R, uint64_t k3_partial,
                     const std::vector<int> &active, uint32_t gamma_u)
{

    // Step 1: E-expand R to 48 bits (pre-provided — do not modify).
    uint64_t expanded = 0;
    for (int i = 0; i < 48; i++)
    {
        int bit = (R >> (31 - E_TABLE[i])) & 1;
        expanded |= ((uint64_t)bit << (47 - i));
    }

    // TODO: Implement Steps 2, 3, and 4 as described above.

    return 0; // placeholder
}

// ============================================================
// FUNCTION 3:  compute_observable
//
// Compute the 1-bit observable value OBS(P, C) for a single
// known plaintext-ciphertext pair.
//
// Mathematical definition (derived in the Background section):
//
//   OBS = parity(P_R, Γ_P)  ⊕  parity(P_L, Γ_U)  ⊕  parity(C_L, Γ_U)
//
// This bit is approximately equal to  K₁_parity ⊕ parity(A₃, Γ_U).
// When the correct K₃ is guessed in the attack loop:
//   - partial_F_parity cancels out the A₃ term.
//   - What remains (OBS ⊕ v) approximates K₁_parity — a biased bit.
//
// Input:
//   P_L, P_R — 32-bit left and right halves of the plaintext
//   C_L      — 32-bit left half of the ciphertext
//   gamma_p  — GAMMA_P mask
//   gamma_u  — GAMMA_U mask
//
// Output:
//   A single bit (0 or 1).
//
// Algorithm (pseudocode):
//   Compute and XOR three dot-product parities using parity32():
//     term1 = parity32(P_R,  gamma_p)
//     term2 = parity32(P_L,  gamma_u)
//     term3 = parity32(C_L,  gamma_u)
//   Return term1 XOR term2 XOR term3.
// ============================================================
int compute_observable(uint32_t P_L, uint32_t P_R, uint32_t C_L,
                       uint32_t gamma_p, uint32_t gamma_u)
{

    // TODO: Implement the three-term XOR of parity dot-products above.

    return 0; // placeholder
}

// ============================================================
// FUNCTION 4:  key_recovery_attack
//
// Recover the partial round-3 subkey bits covering the active
// S-Boxes, using Matsui's Algorithm 2.
//
// Input:
//   pairs   — N known (PT, CT) pairs from generate_known_pairs()
//             Each uint64_t is packed as (LEFT_HALF << 32) | RIGHT_HALF.
//   gamma_p — GAMMA_P mask
//   gamma_u — GAMMA_U mask
//   epsilon — linear bias ε₁ (used to compute the expected score)
//
// Output:
//   The best candidate partial subkey K₃* (uint64_t), packed MSB-first
//   over the active S-Boxes (same packing as k3_partial in Function 2).
//
// Algorithm (pseudocode):
//
//   Step 1 — Determine active S-Boxes and search space:
//     Call identify_active_sboxes(gamma_u) to obtain the active list.
//     num_bits = 6 * number_of_active_SBoxes.
//     Total candidates to test = 2^num_bits.
//     Print which S-Boxes are active and how many bits are being guessed.
//
//   Step 2 — Key-guessing loop:
//     For each candidate k from 0 to (2^num_bits − 1):
//
//       count = 0
//       For each (pt, ct) pair:
//         Extract P_L = upper 32 bits of pt,  P_R = lower 32 bits of pt.
//         Extract C_L = upper 32 bits of ct,  C_R = lower 32 bits of ct.
//         obs = compute_observable(P_L, P_R, C_L, gamma_p, gamma_u)
//         v   = partial_F_parity(C_R, k, active, gamma_u)
//         If (obs XOR v) equals 0: increment count.
//
//       score(k) = |count − N/2|
//
//   Step 3 — Select and report the winner:
//     Print the top-5 (candidate, score) pairs sorted by score descending.
//     Print the theoretical expected score for the correct key: N * |epsilon|.
//     Return the candidate with the highest score.
//
// Note on feasibility:
//   For a single active S-Box, num_bits = 6, giving only 64 candidates —
//   trivially fast.  Two active S-Boxes → 4096 candidates.
//   Each additional S-Box multiplies the search space by 64.
// ============================================================
uint64_t key_recovery_attack(const std::vector<std::pair<uint64_t, uint64_t>> &pairs,
                             uint32_t gamma_p, uint32_t gamma_u, double epsilon)
{

    // TODO: Implement Steps 1 through 3 as described above.

    return 0; // placeholder
}

// ============================================================
// PRE-PROVIDED: print_recovered_key_bits
//
// Displays the recovered partial-K₃ bits alongside the actual
// K₃ bits (derived from the master key) for each active S-Box,
// and reports whether each 6-bit slice matches.
// ============================================================
void print_recovered_key_bits(uint64_t best_k3, const std::vector<int> &active,
                              uint64_t master_key)
{
    auto rkeys = generate_round_keys(master_key, 3);
    uint64_t K3 = rkeys[2];
    int n = (int)active.size();

    std::cout << "\n============================================================\n";
    std::cout << " Key Recovery Results\n";
    std::cout << "============================================================\n";
    std::cout << " Bits recovered: " << (6 * n) << "  (6 bits per active S-Box)\n";
    std::cout << " Active S-Boxes in round 3: ";
    for (int b : active)
        std::cout << "S" << (b + 1) << " ";
    std::cout << "\n\n";

    for (int idx = 0; idx < n; idx++)
    {
        int b = active[idx];
        int recovered = (int)((best_k3 >> (6 * (n - 1 - idx))) & 0x3F);
        int actual = (int)((K3 >> (42 - 6 * b)) & 0x3F);

        std::cout << " S-Box " << (b + 1) << ":\n";
        std::cout << "   Recovered K3 bits : 0b";
        for (int j = 5; j >= 0; j--)
            std::cout << ((recovered >> j) & 1);
        std::cout << "  (0x" << std::hex << recovered << std::dec << ")\n";
        std::cout << "   Actual    K3 bits : 0b";
        for (int j = 5; j >= 0; j--)
            std::cout << ((actual >> j) & 1);
        std::cout << "  (0x" << std::hex << actual << std::dec << ")\n";
        std::cout << "   Match: " << (recovered == actual ? "YES" : "NO") << "\n\n";
    }
}

// ============================================================
// MAIN
// ============================================================
int main()
{
    srand(42); // fixed seed — change to experiment with different keys

    std::cout << "============================================================\n";
    std::cout << " Task 3: Key Recovery Attack on 3-Round DES\n";
    std::cout << " Matsui Algorithm 2 — Linear Cryptanalysis\n";
    std::cout << "============================================================\n";

    // --- Step 1: Display the linear trail parameters from Task 2 ---
    std::cout << "\n[1] Linear trail parameters (from Task 2):\n";
    std::cout << std::hex << std::setfill('0');
    std::cout << "    BEST_SBOX : S-Box " << std::dec << (BEST_SBOX + 1) << "\n";
    std::cout << "    BEST_ALPHA: 0x" << std::hex << std::setw(2) << BEST_ALPHA << "\n";
    std::cout << "    BEST_BETA : 0x" << std::setw(1) << BEST_BETA << "\n";
    std::cout << "    GAMMA_P   : 0x" << std::setw(8) << GAMMA_P << "\n";
    std::cout << "    GAMMA_U   : 0x" << std::setw(8) << GAMMA_U << "\n";
    std::cout << std::dec << std::setfill(' ') << std::fixed << std::setprecision(4);
    std::cout << "    EPSILON   : " << EPSILON
              << "  (|eps| = " << std::abs(EPSILON) << ")\n";

    if (GAMMA_P == 0 && GAMMA_U == 0)
    {
        std::cout << "\n    WARNING: GAMMA_P and GAMMA_U are both 0.\n"
                  << "    Fill in the correct values from Task 2 before running.\n";
    }

    // --- Step 2: Generate a random 64-bit master key ---
    uint64_t master_key = ((uint64_t)rand() << 32) | rand();
    std::cout << "\n[2] Master key: 0x" << std::hex
              << std::setw(16) << std::setfill('0') << master_key
              << std::dec << std::setfill(' ') << "\n";

    // --- Step 3: Generate known plaintext-ciphertext pairs ---
    //
    // The number of pairs N required for the attack to succeed with
    // high probability scales as N ≈ 8 / ε².
    // Example: |ε| = 0.10 → N ≈ 800.   |ε| = 0.03 → N ≈ 8900.
    //
    // TODO: Choose N based on your EPSILON from Task 2.
    //       Increase N if the attack does not recover the correct key.

    int N = 10000; // TODO: set based on your EPSILON
    std::cout << "[3] Generating " << N << " known plaintext-ciphertext pairs...\n";
    auto pairs = generate_known_pairs(master_key, N);
    std::cout << "    Done.\n";

    // --- Step 4: Run the key recovery attack ---
    std::cout << "\n[4] Running key recovery attack...\n";

    // TODO: Call key_recovery_attack() with the parameters above
    //       and store the result in best_k3.

    uint64_t best_k3 = 0; // placeholder — replace with your call

    // --- Step 5: Verify the recovered key bits ---

    // TODO: Call identify_active_sboxes(GAMMA_U) to obtain the active
    //       S-Box list, then pass it along with best_k3 and master_key
    //       to print_recovered_key_bits() to display and verify results.

    std::cout << "\n[5] Attack complete.\n";

    // --- Step 6 (bonus): Analyse the effect of sample size ---
    // Re-run the attack with N/4, N/2, N, 2N samples.
    // Record Score(correct_key) for each run and plot Score vs N.
    // Verify that the relationship is approximately Score ≈ N * |ε|.

    return 0;
}
