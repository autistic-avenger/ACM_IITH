// #include "BUILD_LAT.h"
#include <iostream>
#include <vector>
#include <iomanip>
#include <cmath>
#include <string>

using namespace std;

const int WEAK_S_BOXES[8][4][16] = {
    // S-Box 1
    {{14, 1, 6, 3, 8, 5, 7, 10, 13, 9, 15, 12, 2, 4, 11, 0},
     {15, 14, 2, 3, 4, 5, 7, 8, 6, 9, 0, 11, 12, 13, 1, 10},
     {15, 1, 5, 3, 7, 2, 8, 13, 4, 9, 6, 11, 14, 10, 12, 0},
     {4, 1, 5, 3, 8, 2, 6, 7, 10, 9, 15, 11, 12, 13, 14, 0}},

    // S-Box 2
    {{4, 12, 10, 3, 5, 1, 6, 2, 8, 9, 14, 11, 0, 13, 7, 15},
     {12, 11, 9, 3, 14, 13, 6, 7, 8, 2, 10, 4, 0, 5, 1, 15},
     {5, 14, 2, 13, 6, 4, 11, 15, 12, 9, 3, 0, 1, 10, 8, 7},
     {1, 14, 2, 10, 7, 5, 6, 0, 8, 9, 12, 11, 4, 13, 3, 15}},

    // S-Box 3
    {{14, 12, 6, 3, 4, 5, 2, 7, 8, 9, 15, 11, 0, 13, 1, 10},
     {0, 1, 2, 8, 13, 9, 10, 7, 3, 6, 12, 11, 4, 5, 14, 15},
     {4, 1, 5, 3, 13, 2, 11, 7, 15, 9, 12, 0, 6, 8, 14, 10},
     {0, 6, 2, 3, 7, 15, 10, 4, 13, 9, 1, 11, 14, 8, 12, 5}},

    // S-Box 4
    {{12, 1, 0, 14, 4, 5, 6, 3, 10, 9, 2, 13, 8, 11, 7, 15},
     {0, 1, 2, 15, 4, 5, 8, 7, 9, 12, 10, 11, 3, 13, 14, 6},
     {3, 1, 2, 0, 9, 5, 11, 7, 6, 4, 13, 15, 14, 10, 12, 8},
     {0, 1, 9, 3, 4, 5, 2, 7, 11, 15, 10, 8, 13, 12, 6, 14}},

    // S-Box 5
    {{14, 1, 7, 3, 8, 5, 6, 2, 4, 9, 10, 11, 0, 13, 12, 15},
     {2, 5, 14, 3, 9, 4, 11, 7, 8, 1, 13, 6, 15, 10, 0, 12},
     {0, 1, 5, 13, 7, 12, 10, 4, 3, 9, 2, 11, 14, 6, 8, 15},
     {12, 1, 6, 9, 2, 5, 3, 8, 13, 7, 14, 0, 4, 11, 10, 15}},

    // S-Box 6
    {{0, 5, 2, 3, 8, 1, 6, 7, 4, 9, 15, 11, 12, 13, 14, 10},
     {0, 1, 14, 3, 4, 5, 11, 10, 12, 9, 7, 6, 8, 13, 2, 15},
     {12, 1, 2, 3, 4, 0, 11, 7, 6, 9, 15, 8, 5, 13, 14, 10},
     {6, 3, 2, 1, 4, 5, 10, 7, 8, 9, 14, 11, 15, 13, 0, 12}},

    // S-Box 7
    {{2, 3, 1, 6, 5, 7, 4, 6, 9, 8, 11, 10, 13, 15, 14, 12},
     {1, 0, 2, 3, 5, 4, 7, 6, 10, 11, 8, 9, 15, 12, 13, 14},
     {1, 2, 3, 0, 4, 7, 5, 6, 8, 10, 9, 11, 12, 14, 15, 13},
     {2, 1, 0, 3, 5, 7, 6, 4, 8, 10, 13, 9, 13, 14, 12, 15}},

    // S-Box 8
    {{12, 14, 7, 3, 9, 5, 6, 2, 10, 4, 8, 11, 1, 13, 0, 15},
     {0, 11, 7, 3, 15, 5, 6, 2, 8, 9, 10, 1, 12, 13, 14, 4},
     {0, 1, 9, 14, 4, 2, 10, 5, 13, 7, 15, 11, 12, 8, 3, 6},
     {0, 1, 2, 3, 7, 5, 6, 4, 14, 11, 13, 9, 8, 10, 12, 15}}};

// Function 01: extract_row

int extract_row(int input)
{

}

// Function 02: extract_col

int extract_col(int input)
{
    // write your logic here
}

// FUNCTION 3: dot_product (inner product mod 2)

// Purpose : Compute the bitwise inner product of two integers mod 2.
//           This is the XOR of all bits in (value & mask).

int dot_product(int value, int mask, int num_bits)
{
    int result = 0;
    for (int i = 0; i < num_bits; ++i)
    {

    }
    return result;
}

// FUNCTION 4: compute_lat

// Purpose : Build the full Linear Approximation Table for one S-Box.

vector<vector<int>> compute_lat(const int sbox[4][16])
{

    vector<vector<int>> lat(64, vector<int>(16, 0));
    // Step 01: Iterate over all 64 possible 6-bit inputs X  and Look up S-Box output for this input X

    // code your logic for step 01

    // Step 2: For every input mask alpha and output mask beta,
    //         test whether the linear approximation holds for this X

    // STEP 2.1: Compute left side of approximation: alpha · X  (1 bit) FOR EVERY ALPHA

    // WRITE YOUR LOGIC FOR STEP 2.1

    // STEP: 2.2 Compute right side: beta · S(X)  (1 bit) for every beta

    // WRITE YOUR LOGIC FOR STEP 2.2

    // STP 2.3: Approximation holds when both parities match
    // Increment count; we subtract 32 after the full loop

    // WRITE YOUR LOGIC FOR STEP 2.3

}


// STEP 03: Convert raw counts to biases: bias = count - 32
// After this, the trivial entry lat[0][0] becomes +32 (was 64).
// All entries with alpha=0, beta=0 trivially satisfy 0 = 0 for all X.

// write your logic here FOR STEP 03

// FUNCTION 5: find_max_bias


// Purpose : Search the LAT for the strongest (non-trivial) linear
//           approximation and report its location and value.
int find_max_bias(const vector<vector<int>> &lat,
                  int &best_alpha, int &best_beta)
{
    int max_abs_bias = 0;
    best_alpha = 0;
    best_beta = 0;

    // WRITE YOUR LOGIC HERE
    return max_abs_bias;
}

// FUNCTION 6: print_lat_table

void print_lat_table(const vector<vector<int>> &lat, int sbox_index)
{

    cout << "\n";
    cout << "============================================================\n";
    cout << " Linear Approximation Table  --  S-Box " << sbox_index + 1 << "\n";
    cout << " (cell values = bias = count - 32,  range: -32 to +32)\n";
    cout << "============================================================\n";

    // --- Header row: output masks beta in hex ---
    cout << " Alpha \\ Beta |";
    for (int beta = 0; beta < 16; ++beta)
    {
        cout << setw(4) << hex << beta << dec;
    }
    cout << "\n";
    cout << " " << string(14 + 16 * 4, '-') << "\n";

    // --- Data rows: one per input mask alpha ---
    for (int alpha = 0; alpha < 64; ++alpha)
    {
        cout << setw(12) << dec << alpha << "  |";
        for (int beta = 0; beta < 16; ++beta)
        {
            cout << setw(4) << lat[alpha][beta];
        }
        cout << "\n";
    }

    // --- Summary: strongest non-trivial linear approximation ---
    int best_alpha, best_beta;
    int max_abs_bias = find_max_bias(lat, best_alpha, best_beta);
    int raw_count = max_abs_bias + 32;                          // back to count (0..64)
    double epsilon = (double)lat[best_alpha][best_beta] / 64.0; // Matsui's eps

    cout << "\n Best non-trivial approximation:\n";
    cout << "   Input  mask alpha = " << best_alpha
              << "  (0x" << hex << best_alpha << dec << ")\n";
    cout << "   Output mask beta  = " << best_beta
              << "  (0x" << hex << best_beta << dec << ")\n";
    cout << "   Bias              = " << lat[best_alpha][best_beta]
              << "  (raw count = " << raw_count << " / 64)\n";
    cout << fixed << setprecision(4);
    cout << "   Epsilon (bias/64) = " << epsilon << "\n";
    cout << "   |Epsilon|         = " << abs(epsilon) << "\n";
}

// MAIN FUNCTION

int main()
{

    cout << "DES Linear Approximation Table (LAT) Generator\n";
    cout << "Using custom weak S-Boxes from the cryptanalysis assignment\n";

    for (int i = 0; i < 8; ++i)
    {

        // Step 1: compute the LAT (bias-centered, -32..+32)
        vector<vector<int>> lat = compute_lat(WEAK_S_BOXES[i]);

        // Step 2: print the full table and summary
        print_lat_table(lat, i);
    }

    return 0;
}
