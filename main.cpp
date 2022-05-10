#include "KCipher.h"
#include <iostream>
#include <random>
#include <chrono>
#include <cmath>

/*
 * These variables are global for the sake of efficiency of the code.
 */
KCipher kcipher;
bitset<N> r[6];
bitset<K> key;
bitset<N> round_keys[3];
uint64_t key_table[1 << M][1 << M];
const int num_of_exp = 14;
bitset<N> P[1<<num_of_exp];
bitset<N> C[1<<num_of_exp];
struct characteristic {
    uint32_t input_diff;
    uint32_t output_diff;
    uint32_t sbox;
    double probability;
};

/*
 * random device engine, usually based on /dev/random on UNIX-like systems
 * initialize Mersennes' twister using rd to generate the seed
*/
static std::random_device rd;
static std::mt19937 rng{rd()};
template<size_t size>
void Random(bitset<size> &input) {
    static std::uniform_int_distribution<int> uid(0, 1); // random dice
    for (int i = 0; i < size; i++)
        input[i] = uid(rng);
}

void Init() {
    string key_string = "001011001011111011010001111001000101100101111010100101011100111000100101010111000001011100000011";
    bitset<K> temp(key_string);
    key = temp;
    bitset<N> rand2[6];
    rand2[0] = 0x4d82b5;
    rand2[1] = 0xdb8760;
    rand2[2] = 0xffffff;
    rand2[3] = 0x71fc2a;
    rand2[4] = 0x4dfa7d;
    rand2[5] = 0xa92a9a;
    for (int i = 0; i < 6; i++)
        r[i] = rand2[i];
    kcipher.init(key);
    for (uint32_t i = 0; i < (1<<num_of_exp); i++) {
        Random(P[i]);
        C[i] = kcipher.EncCPA(P[i], key, r);
    }
}

inline uint8_t partial_dec(bitset<N> ct, uint8_t r1, uint8_t k, int position, int round) {
    bitset<M> temp;
    for (int i = 0; i < M; i++) {
        temp[i] = ct[N - 8 * position + i];
    }
    uint8_t block_val = temp.to_ulong();
    if(round <= 2){
        //(s[x] + r) >> 2 + k
        // s[x] >> 2 + r >> 2  + k
        block_val ^= r1;
        block_val -= k;
        // ct - (k2 + (r11 >> 2))
        block_val = ROTR8(block_val, 2);
        block_val = kcipher.sbox_inv[block_val];
        return block_val;
    }
    if(round == 3) {
        block_val ^= k;
        block_val = ROTR8(block_val, 2);
        block_val -= r1;
        block_val = kcipher.sbox_inv[block_val];
        return block_val;
    }
    return 0;
}

inline void differential_cryptanalysis_key_recovery(characteristic c, int idx, int round) {
    /*
     * key recovery function recovers the last round key and randomizer
     */
    bitset<N> p[2];
    bitset<N> ciphertext[2];
    p[0] = P[idx];
    p[1] = p[0];
    p[1][c.input_diff] = p[1][c.input_diff] ^ 1;
    if(round > 1) {
        ciphertext[0] = C[idx];
        ciphertext[1] = kcipher.EncCPA(p[1], key, r);
        for (int i = 0; i < 2; i++) {
            if (round == 2) {
                // veil = k[3] = bitreordering(k[2], 3);
                bitset<N> veil = kcipher.BitReordering(kcipher.round_keys[2], 3);
                ciphertext[i] = ciphertext[i] ^ veil;
                ciphertext[i] = kcipher.Inv_SBox(ciphertext[i], r, 2);
                // now we have ciphertext after bitreordering 2
                ciphertext[i] = ciphertext[i] ^ r[4];
                ciphertext[i] = kcipher.BitReorderingRev(ciphertext[i], 2);
                // These amount of decryption is allowed because we already recovered K[3], K[2], and r[5] = r12
            }
        }
    }
    else if (round == 1){
        for(int i = 0; i < 2; i++){
            ciphertext[i] = p[i] + kcipher.round_keys[0];
            ciphertext[i] = kcipher.BitReordering(ciphertext[i], 0);
            ciphertext[i] = kcipher.SBox(ciphertext[i], r, 0);
            ciphertext[i] = ciphertext[i] + kcipher.round_keys[1];
            ciphertext[i] = kcipher.BitReordering(ciphertext[i], 1);
            ciphertext[i] = kcipher.SBox(ciphertext[i], r, 1);
            ciphertext[i] = kcipher.Inv_SBox(ciphertext[i], r, 1);
            // now we have ciphertext after bitreordering 2
            ciphertext[i] = ciphertext[i] ^ r[2];
            ciphertext[i] = kcipher.BitReorderingRev(ciphertext[i], 1);

        }
    }
    uint8_t res[2];
    uint8_t expected_difference = 1 << (c.output_diff % 8);
    for (uint16_t k = 0; k < 256; k++) {
        for (uint16_t r1 = 0; r1 < 256; r1++) {
            res[0] = partial_dec(ciphertext[0], r1, k, c.sbox, round);
            res[1] = partial_dec(ciphertext[1], r1, k, c.sbox, round);
            if ((res[0] ^ res[1]) == expected_difference) {
                key_table[k][r1]++;
            }
        }
    }
}

void differential_cryptanalysis_distinguisher(characteristic c, int round) {
    /*
     * The distinguisher function computes the probability of the characteristic c
     */
    bitset<N> p1, p2, c1, c2;
    int br = 0;
    unsigned int number_of_experiments = pow(2, num_of_exp);
    bitset<N> expected_diff, exp1, exp2;
    for (int i = 0; i < N; i++) {
        expected_diff[i] = 0;
        exp1[i] = 0;
        exp2[i] = 0;
    }
    expected_diff.set(c.output_diff);
    for (int i = 0; i < number_of_experiments; i++) {
        p1 = P[i];
        p2 = p1;
        p2[c.input_diff] = p2[c.input_diff] ^ 1;
        c1 = p1 + kcipher.round_keys[0];
        c2 = p2 + kcipher.round_keys[0];
        c1 = kcipher.BitReordering(c1, 0);
        c2 = kcipher.BitReordering(c2, 0);
        if(round >= 2) {
            c1 = kcipher.SBox(c1, r, 0);
            c2 = kcipher.SBox(c2, r, 0);

            //round 2
            c1 = c1 + kcipher.round_keys[1];
            c2 = c2 + kcipher.round_keys[1];

            c1 = kcipher.BitReordering(c1, 1);
            c2 = kcipher.BitReordering(c2, 1);
            if (round == 3) {
                c1 = kcipher.SBox(c1, r, 1);
                c2 = kcipher.SBox(c2, r, 1);
                c1 = c1 + kcipher.round_keys[2];
                c2 = c2 + kcipher.round_keys[2];
                c1 = kcipher.BitReordering(c1, 2);
                c2 = kcipher.BitReordering(c2, 2);
            }
        }
        if ((c1 ^ c2) == expected_diff) {
            br++;
        }
    }
    double proball = (double) br / number_of_experiments;
    proball = log2(proball);
    c.probability = proball;
    cout << dec << "Characteristic: " << c.input_diff << " -> " << c.output_diff << " on sbox number: " << c.sbox
         << " holds with probability: 2^" << c.probability << endl;
}

void attack_round_3() {
    uint8_t c_arr_1[3][3] = {{22,  16, 1},
                             {15,  13, 2},
                             {19, 2, 3}};

    for (int t = 0; t < 3; t++) {
        for (int i = 0; i < 256; i++)
            for (int j = 0; j < 256; j++)
                key_table[i][j] = 0;
        characteristic c;
        c.input_diff = c_arr_1[t][0];
        c.output_diff = c_arr_1[t][1];
        c.sbox = c_arr_1[t][2];
        /*
         * uncomment the following function call to run the distinguisher attack.
         */
        //differential_cryptanalysis_distinguisher(c, 3);
        for (int i = 0; i < (1 << num_of_exp); i++) {
            differential_cryptanalysis_key_recovery(c, i, 3);
        }
        int maxk = 0, maxr1 = 0;
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                if (key_table[i][j] > key_table[maxk][maxr1]) {
                    maxk = i;
                    maxr1 = j;
                }
            }
        }
        cout << c.input_diff << "\t" << c.output_diff << "\t" << c.probability << "\t" << c.sbox << endl;
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                if (key_table[i][j] == key_table[maxk][maxr1]) {
                    cout << hex << i << "\t" << j << "\t" << key_table[i][j] << endl;
                }
            }
        }
        cout << "\n________________________\n";
    }
}

void attack_round_2() {
    uint8_t c_arr_1[3][3] = {{22,  11, 2},
                             {15,  18, 1},
                             {19, 0, 3}};
    for (int t = 0; t < 3; t++) {
        for (int i = 0; i < 256; i++)
            for (int j = 0; j < 256; j++)
                key_table[i][j] = 0;
        characteristic c;
        c.input_diff = c_arr_1[t][0];
        c.output_diff = c_arr_1[t][1];
        c.sbox = c_arr_1[t][2];
        /*
         * uncomment the following function call to run the distinguisher attack.
         */
//        differential_cryptanalysis_distinguisher(c, 2);
        for (int i = 0; i < (1 << (num_of_exp-2)); i++) {
            differential_cryptanalysis_key_recovery(c, i, 2);
        }
        int maxk = 0, maxr1 = 0;
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                if (key_table[i][j] > key_table[maxk][maxr1]) {
                    maxk = i;
                    maxr1 = j;
                }
            }
        }
        cout << c.input_diff << "\t" << c.output_diff << "\t" << c.probability << "\t" << c.sbox << endl;
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                if (key_table[i][j] == key_table[maxk][maxr1]) {
                    cout << hex << i << "\t" << j << "\t" << key_table[i][j] << endl;
                }
            }
        }
        cout << "\n________________________\n";
    }
}

void attack_round_1() {
    uint8_t c_arr_1[3][3] = {{22,  17, 1},
                             {18,  5, 3},
                             {15, 8, 2}};
    for (int t = 0; t < 3; t++) {
        for (int i = 0; i < 256; i++)
            for (int j = 0; j < 256; j++)
                key_table[i][j] = 0;
        characteristic c;
        c.input_diff = c_arr_1[t][0];
        c.output_diff = c_arr_1[t][1];
        c.sbox = c_arr_1[t][2];
        /*
         * uncomment the following function call to run the distinguisher attack.
         */
//        differential_cryptanalysis_distinguisher(c, 1);
        for (int i = 0; i < (1 << 8); i++) {
            differential_cryptanalysis_key_recovery(c, i, 1);
        }
        int maxk = 0, maxr1 = 0;
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                if (key_table[i][j] > key_table[maxk][maxr1]) {
                    maxk = i;
                    maxr1 = j;
                }
            }
        }
        cout << c.input_diff << "\t" << c.output_diff << "\t" << c.probability << "\t" << c.sbox << endl;
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                if (key_table[i][j] == key_table[maxk][maxr1]) {
                    cout << hex << i << "\t" << j << "\t" << key_table[i][j] << endl;
                }
            }
        }
        cout << "\n________________________\n";
    }
}

using namespace std;
using chrono::high_resolution_clock;
using chrono::duration_cast;
using chrono::duration;
using chrono::milliseconds;

int main(int argc, char **argv) {
    Init();
    ios_base::sync_with_stdio(false);
    auto t1 = high_resolution_clock::now();
    attack_round_3();
    auto t2 = high_resolution_clock::now();
    duration<double, std::milli> ms_double = t2 - t1;
    cout << "The attack round 3 finished in(ms):" << ms_double.count() << endl;

    t1 = high_resolution_clock::now();
    attack_round_2();
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "The attack round 2 finished in(ms):" << ms_double.count() << endl;

    t1 = high_resolution_clock::now();
    attack_round_1();
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "The attack round 1 finished in(ms):" << ms_double.count() << endl;

    return 0;
}
