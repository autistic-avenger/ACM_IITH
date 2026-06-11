#include <iostream>
#include <vector>
#include <cstdint>
#include <cmath>
#include <iomanip>
#include <algorithm>
#include <random>

using namespace std;
// ============================================================
// Weak S-boxes (same as Tasks 1-3)
// ============================================================
static const int WEAK_S_BOXES[8][4][16] = {
    {{14, 1, 6, 3, 8, 5, 7, 10, 13, 9, 15, 12, 2, 4, 11, 0}, {15, 14, 2, 3, 4, 5, 7, 8, 6, 9, 0, 11, 12, 13, 1, 10}, {15, 1, 5, 3, 7, 2, 8, 13, 4, 9, 6, 11, 14, 10, 12, 0}, {4, 1, 5, 3, 8, 2, 6, 7, 10, 9, 15, 11, 12, 13, 14, 0}},
    {{4, 12, 10, 3, 5, 1, 6, 2, 8, 9, 14, 11, 0, 13, 7, 15}, {12, 11, 9, 3, 14, 13, 6, 7, 8, 2, 10, 4, 0, 5, 1, 15}, {5, 14, 2, 13, 6, 4, 11, 15, 12, 9, 3, 0, 1, 10, 8, 7}, {1, 14, 2, 10, 7, 5, 6, 0, 8, 9, 12, 11, 4, 13, 3, 15}},
    {{14, 12, 6, 3, 4, 5, 2, 7, 8, 9, 15, 11, 0, 13, 1, 10}, {0, 1, 2, 8, 13, 9, 10, 7, 3, 6, 12, 11, 4, 5, 14, 15}, {4, 1, 5, 3, 13, 2, 11, 7, 15, 9, 12, 0, 6, 8, 14, 10}, {0, 6, 2, 3, 7, 15, 10, 4, 13, 9, 1, 11, 14, 8, 12, 5}},
    {{12, 1, 0, 14, 4, 5, 6, 3, 10, 9, 2, 13, 8, 11, 7, 15}, {0, 1, 2, 15, 4, 5, 8, 7, 9, 12, 10, 11, 3, 13, 14, 6}, {3, 1, 2, 0, 9, 5, 11, 7, 6, 4, 13, 15, 14, 10, 12, 8}, {0, 1, 9, 3, 4, 5, 2, 7, 11, 15, 10, 8, 13, 12, 6, 14}},
    {{14, 1, 7, 3, 8, 5, 6, 2, 4, 9, 10, 11, 0, 13, 12, 15}, {2, 5, 14, 3, 9, 4, 11, 7, 8, 1, 13, 6, 15, 10, 0, 12}, {0, 1, 5, 13, 7, 12, 10, 4, 3, 9, 2, 11, 14, 6, 8, 15}, {12, 1, 6, 9, 2, 5, 3, 8, 13, 7, 14, 0, 4, 11, 10, 15}},
    {{0, 5, 2, 3, 8, 1, 6, 7, 4, 9, 15, 11, 12, 13, 14, 10}, {0, 1, 14, 3, 4, 5, 11, 10, 12, 9, 7, 6, 8, 13, 2, 15}, {12, 1, 2, 3, 4, 0, 11, 7, 6, 9, 15, 8, 5, 13, 14, 10}, {6, 3, 2, 1, 4, 5, 10, 7, 8, 9, 14, 11, 15, 13, 0, 12}},
    {{2, 3, 1, 6, 5, 7, 4, 6, 9, 8, 11, 10, 13, 15, 14, 12}, {1, 0, 2, 3, 5, 4, 7, 6, 10, 11, 8, 9, 15, 12, 13, 14}, {1, 2, 3, 0, 4, 7, 5, 6, 8, 10, 9, 11, 12, 14, 15, 13}, {2, 1, 0, 3, 5, 7, 6, 4, 8, 10, 13, 9, 13, 14, 12, 15}},
    {{12, 14, 7, 3, 9, 5, 6, 2, 10, 4, 8, 11, 1, 13, 0, 15}, {0, 11, 7, 3, 15, 5, 6, 2, 8, 9, 10, 1, 12, 13, 14, 4}, {0, 1, 9, 14, 4, 2, 10, 5, 13, 7, 15, 11, 12, 8, 3, 6}, {0, 1, 2, 3, 7, 5, 6, 4, 14, 11, 13, 9, 8, 10, 12, 15}}};

// DES tables (1-indexed values; subtract 1 for 0-indexed bit positions)
static const int E_TABLE[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
static const int P_TABLE[32] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};

// ============================================================
// Low-level helpers
// ============================================================

// PURPOSE: Compute the parity (XOR of all bits) of a 32-bit value.
//   Returns 0 if the number of set bits is even, 1 if odd.
//   This is the fundamental operation of linear cryptanalysis: a "dot product
//   mod 2". Used everywhere to evaluate parity(mask & value).
static inline int parity(uint32_t v) { return __builtin_parity(v); }

// PURPOSE: Decode the 2-bit ROW index from a 6-bit S-box input.
//   DES rule: row = { bit5 (outermost), bit0 (innermost) }.
//   Together with extract_col, this maps a 6-bit input to an SBOX[][] cell.

int extract_row(int input)
{
    int first_bit  = (input>>5) &1;
    int last_bit = input & 1;
    int row_ = first_bit <<1 | last_bit;
    return row_;
}


    // PURPOSE: Decode the 4-bit COLUMN index from a 6-bit S-box input.
    //   DES rule: col = the inner 4 bits (bits 4..1).
int extract_col(int input)
{
    return input>>1 & 0xF;
}
    // PURPOSE: Compute the inner product (mod 2) of value and mask over `bits` bits.
//   Returns parity( value & mask ) restricted to the low `bits` positions.
//   Used by compute_lat to evaluate "alpha . X" and "beta . S(X)".
int dot_product(int value, int mask, int num_bits)
{
    int ttt = value &mask ;
    int result = 0;
    for (int i = 0; i < num_bits; ++i)
    {
        result ^= (ttt>>i) & 1;
    }
    return result;
}
// PURPOSE: Look up the 4-bit output of S-box b for a 6-bit input x.
//   Convenience wrapper that decodes row/col and indexes the S-box table.
static inline int sbox_val(int b, int x) { return WEAK_S_BOXES[b][extract_row(x)][extract_col(x)]; }
// PURPOSE: Apply the DES E-expansion, turning the 32-bit right half R into a
//   48-bit block (the input to the 8 S-boxes, before key XOR).
//   Each output position i is copied from R bit E_TABLE[i]-1. Some R bits are
//   duplicated (16 boundary bits feed two positions) — this is what later
//   lets a single R-bit mask activate two S-boxes.
static uint64_t expand(uint32_t R)
{
    uint64_t o = 0;
    for (int i = 0; i < 48; ++i)
    {
        int s = E_TABLE[i] - 1;
        o |= ((uint64_t)((R >> (31 - s)) & 1) << (47 - i));
    }
    return o;
}
// PURPOSE: Apply the DES P-permutation: a pure 32->32 bit shuffle of the
//   S-box output layer. Output bit i comes from S-box-layer bit P_TABLE[i]-1.
//   Because it is a permutation (no bit mixing), dot products are preserved
//   through it — the fact that lets beta_to_Fmask just relocate mask bits.
static uint32_t permute_P(uint32_t in)
{
    uint32_t o = 0;
    for (int i = 0; i < 32; ++i)
    {
        int s = P_TABLE[i] - 1;
        o |= (((in >> (31 - s)) & 1) << (31 - i));
    }
    return o;
}
// PURPOSE: The full DES round function F(R, K).
//   Pipeline: E-expand R (32->48) -> XOR round key K -> 8 S-boxes (6->4 each)
//   -> P-permutation (32->32). Returns the 32-bit F output.
//   Used by the empirical verifier to actually encrypt and check the trail.
static uint32_t F_function(uint32_t R, uint64_t K)
{
    uint64_t x = expand(R) ^ K;
    uint32_t s = 0;
    for (int b = 0; b < 8; ++b)
    {
        int sh = 42 - b * 6;
        s |= (sbox_val(b, (x >> sh) & 0x3F) << (28 - b * 4));
    }
    return permute_P(s);
}
// ============================================================
// PURPOSE: Build the Linear Approximation Table (LAT) for one S-box.
//   For every input mask alpha (0..63) and output mask beta (0..15), count how
//   many of the 64 inputs X satisfy parity(alpha.X) == parity(beta.S(X)), then
//   store the BIAS = count - 32 (range -32..+32). A large |bias| means a strong
//   linear approximation. This is the Task-1 LAT, reused here as the source of
//   per-S-box approximations the trail search picks from.
// ============================================================
vector<vector<int>> compute_lat(const int sbox[4][16]){
    vector<vector<int>> lat(64, vector<int>(16, 0));
    for (int x = 0; x < 64; x++)
    {
        int row = extract_row(x);
        int col = extract_col(x);
        int sx = sbox[row][col];
        for (int alpha = 0; alpha < 64; alpha++)
        {
            int left = dot_product(x, alpha, 6);
            for (int beta = 0; beta < 16; beta++)
            {
                int right = dot_product(sx, beta, 4);

                if (left == right)
                {
                    lat[alpha][beta]++;
                }
            }
        }
    }

    for (int alpha = 0; alpha < 64; alpha++)
    {
        for (int beta = 0; beta < 16; beta++)
        {
            lat[alpha][beta] -= 32;
        }
    }

    return lat;
}

// ============================================================
// MASK CONSTRUCTION (bit-ordering corrected — see header note)
// ============================================================
// alpha_to_Rmask:
//   PURPOSE: Convert a chosen S-box INPUT mask into a 32-bit mask on R (the
//     plaintext-side right half, BEFORE E-expansion). This is the "forward"
//     direction used to seed round 1.
//   GUARANTEE: parity(Rmask & R) == parity(alpha & sbox_b_input) for every R.
//   HOW: bit j of alpha maps to expanded position b*6 + (5 - j) (the (5-j) is
//     the MSB-first/LSB-first reversal), whose source R-bit is E_TABLE[pos]-1.
uint32_t alpha_to_Rmask(int b, int alpha)
{
    uint32_t m = 0;
    for (int j = 0; j < 6; ++j)
        if (alpha >> j & 1)
        {
            int pos = b * 6 + (5 - j); // reversal: LSB-first read of MSB-first field
            int r_bit = E_TABLE[pos] - 1;
            m ^= (1u << (31 - r_bit));
        }
    return m;
}
// beta_to_Fmask:
//   PURPOSE: Convert a chosen S-box OUTPUT mask into a 32-bit mask on the round
//     function's output (AFTER the P-permutation). This expresses the LAT's
//     beta (which is defined on the S-box output, i.e. the input to P) on the
//     actual 32-bit data that flows to the next round.
//   GUARANTEE: parity(Fmask & F(R)) == parity(beta & sbox_b_output).
//   HOW: bit k of beta sits at 32-bit S-box-layer MSB-position (3 + 4*b - k);
//     P sends that layer bit to F-output bit i where P_TABLE[i]-1 == that pos.
//     Valid because P is a pure permutation, so dot products pass through it.
uint32_t beta_to_Fmask(int b, int beta)
{
    uint32_t m = 0;
    for (int k = 0; k < 4; ++k)
        if (beta >> k & 1)
        {
            int sl_bit = 3 + 4 * b - k; // reversal for the 4-bit output field
            for (int i = 0; i < 32; ++i)
                if (P_TABLE[i] - 1 == sl_bit)
                {
                    m ^= (1u << (31 - i));
                    break;
                }
        }
    return m;
}
// Rmask_to_alphas:
//   PURPOSE: The INVERSE of alpha_to_Rmask, used during propagation. Given a
//     32-bit mask on R (handed forward as the previous round's output), work
//     out which S-boxes that mask makes ACTIVE and what 6-bit input mask alpha
//     each one is forced to use. This is the step that makes "round r's output
//     determines round r+1's active S-boxes" actually happen — the next round
//     does not get to choose its own alpha.
//   NOTE: a single R-bit may feed TWO S-boxes (E-expansion duplicates 16
//     boundary bits), so one set bit can activate two S-boxes. XOR accumulation
//     handles overlaps and cancellations correctly (parity behavior).
vector<pair<int, int>> Rmask_to_alphas(uint32_t rmask)
{
    int alpha[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int pos = 0; pos < 48; ++pos)
    {
        int r_bit = E_TABLE[pos] - 1;
        if (rmask >> (31 - r_bit) & 1)
        {
            int b = pos / 6;
            int j = 5 - (pos % 6); // reversal
            alpha[b] ^= (1 << j);
        }
    }
    vector<pair<int, int>> active;
    for (int b = 0; b < 8; ++b)
        if (alpha[b])
            active.push_back({b, alpha[b]});
    return active;
}
// ============================================================
// STRUCT RoundStep:
//   PURPOSE: Holds the result of approximating ONE round. Records the forced
//   active S-boxes (with their fixed alpha), the searched beta per S-box, the
//   round's 32-bit input and output masks, the round bias, and whether the
//   round is usable. Produced by best_round_given_input.
// ============================================================
struct RoundStep
{
    vector<pair<int, int>> active_alpha; // (sbox, alpha) — forced
    vector<pair<int, int>> active_beta;  // (sbox, beta)  — searched
    uint32_t in_mask;                              // 32-bit mask on this round's R input
    uint32_t out_mask;                             // 32-bit mask on this round's F output
    double eps;                                    // 2^(k-1) * prod(eps_i) over k active S-boxes
    bool valid;                                    // false if any active S-box has no usable (bias=0) approximation
};

// PURPOSE: Find the best linear approximation for ONE round, given that the
//   round's R-input mask is already fixed (handed down by the previous round).
//   The active S-boxes and their input masks alpha are therefore FORCED; the
//   only freedom is the output mask beta per active S-box. For each active
//   S-box we scan beta = 1..15 and keep the one with the largest |bias|, then
//   combine the chosen approximations with the piling-up lemma to get this
//   round's bias and its output mask (which becomes the next round's input).
//   Sets valid=false if any forced S-box has no usable approximation (bias 0),
//   which kills the trail.

RoundStep best_round_given_input(uint32_t in_mask,
                                 const vector<vector<vector<int>>> &all_lats)
{
    // WRITE CODE HERE
}
// ============================================================
// STRUCT Trail:
//   PURPOSE: A full multi-round trail = the ordered list of RoundSteps plus the
//   combined bias and the end-to-end masks. round r's output mask equals round
//   r+1's input mask (propagation). eps_total is the piling-up combination;
//   gamma_P/gamma_U are the plaintext-side and ciphertext-side masks an attack
//   would use. Produced by build_trail.
// ============================================================
struct Trail
{
    vector<RoundStep> steps;
    double eps_total;
    uint32_t gamma_P, gamma_U;
    bool valid;
};
// PURPOSE: Build a complete multi-round trail starting from a given round-1
//   R-input mask. It walks round by round: compute the best constrained
//   approximation for the current round, then PROPAGATE — this round's output
//   mask becomes the next round's R-input mask. Accumulates the overall bias
//   with the piling-up lemma (eps_total = 2^(rounds-1) * product of round eps).
//   Records gamma_P (round 1 input) and gamma_U (last round output) for the
//   key-recovery stage. valid=false if any round along the way died.
Trail build_trail(uint32_t r1_in, int rounds,
                  const vector<vector<vector<int>>> &all_lats)
{
    // WRITE CODE HERE
}
// PURPOSE: Find the strongest valid trail of a given depth. It tries every
//   single-S-box seed (each S-box b with each non-zero alpha) as the round-1
//   starting point, builds the propagated trail from it, and keeps the one with
//   the largest |total bias| among trails that survive all rounds. This is the
//   top-level entry point that answers "what is the best `rounds`-round linear
//   approximation for this cipher?"
Trail search_best_trail(int rounds,
                        const vector<vector<vector<int>>> &all_lats)
{
    // WRITE CODE HERE
}
// ============================================================
// PURPOSE: Independently CHECK that a trail's predicted bias is real.
//   Rather than trusting the piling-up arithmetic, this actually encrypts N
//   random inputs (with zero subkeys, so we test the pure "characteristic"),
//   evaluates the summed per-round linear relation, and measures how often it
//   holds. The returned empirical eps should match the predicted eps within
//   statistical noise (~1/sqrt(N)).
// ============================================================
double verify_trail_empirically(const Trail &t, int N = 500000, uint32_t seed = 99)
{
    mt19937_64 rng(seed);
    // WRITE CODE HERE
}
// ============================================================
// DISPLAY
// ============================================================
// PURPOSE:  per round show the input and output masks, which S-boxes are active with their (alpha, beta), and
//   that round's bias; then the overall predicted bias and the gamma_P /
//   gamma_U masks that a key-recovery attack would consume.
void print_trail(const Trail &t, const string &title)
{
    cout << "\n"
              << title << "\n";
    cout << string(title.size(), '-') << "\n";
    for (size_t r = 0; r < t.steps.size(); ++r)
    {
        const auto &s = t.steps[r];
        cout << " Round " << (r + 1)
                  << ": in=0x" << hex << setw(8) << setfill('0') << s.in_mask
                  << " out=0x" << setw(8) << s.out_mask << dec << setfill(' ')
                  << "  active:";
        for (size_t i = 0; i < s.active_alpha.size(); ++i)
            cout << " S" << (s.active_alpha[i].first + 1)
                      << "(a=0x" << hex << s.active_alpha[i].second
                      << ",b=0x" << s.active_beta[i].second << dec << ")";
        cout << "  round_eps=" << fixed << setprecision(5) << s.eps << "\n";
    }
    cout << " Predicted total eps = " << t.eps_total
              << "  |eps| = " << abs(t.eps_total) << "\n";
    cout << " gamma_P = 0x" << hex << setw(8) << setfill('0') << t.gamma_P
              << "   gamma_U = 0x" << setw(8) << t.gamma_U << dec << setfill(' ') << "\n";
}
// ============================================================
// MAIN
// ============================================================
// ============================================================
// PURPOSE: Orchestrate the whole demonstration:
//   1. Build the LATs for all 8 S-boxes.
//   2. Show how the best achievable bias DEGRADES as depth grows from 1 to 3
//      rounds (the behavior the simplified Task 2 hid).
//   3. Print the best 3-round trail in full.
//   4. Empirically verify that trail's predicted bias against real encryptions.
// ============================================================
int main()
{
    cout << "============================================================\n";
    cout << "  Correct multi-round linear trail search (mask propagation)\n";
    cout << "  3-round Feistel DES, weak S-boxes\n";
    cout << "============================================================\n";
    vector<vector<vector<int>>> all_lats(8);
    for (int b = 0; b < 8; ++b)
        all_lats[b] = compute_lat(WEAK_S_BOXES[b]);
    // Bias degradation across depths (best valid trail at each depth).
    cout << "\nBias degradation with depth (best valid propagated trail):\n";
    cout << "  rounds   |eps|        samples ~1/eps^2\n";
    cout << "  ------   --------     -------------------\n";
    for (int rounds = 1; rounds <= 3; ++rounds)
    {
        Trail t = search_best_trail(rounds, all_lats);
        double e2 = t.eps_total * t.eps_total;
        cout << "    " << rounds << "      "
                  << fixed << setprecision(5) << abs(t.eps_total)
                  << "      " << (e2 > 0 ? (long long)(1.0 / e2) : -1) << "\n";
    }
    // Full 3-round trail, printed and empirically verified.
    Trail t3 = search_best_trail(3, all_lats);
    print_trail(t3, "Best valid 3-round trail");
    cout << "\nEmpirical verification (zero-key characteristic, 500k samples):\n";
    double emp = verify_trail_empirically(t3);
    cout << "  predicted eps = " << fixed << setprecision(5) << t3.eps_total << "\n";
    cout << "  empirical eps = " << emp << "\n";
    cout << "  result        = "
              << (abs(abs(emp) - abs(t3.eps_total)) < 0.01
                      ? "MATCH (trail bias is correct)"
                      : "MISMATCH")
              << "\n";
    return 0;
}