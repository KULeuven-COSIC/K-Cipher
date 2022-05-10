#include <bitset>
#include <cstdint>
#include <iostream>
#include "KCipher.h"

using namespace std;

template<size_t size>
bitset<size> operator+(bitset<size> &A, bitset<size> &B) noexcept {
    bitset<size> SUM;
    bool carry = 0;
    for (int i = 0; i < size; i++) {
        SUM[i] = A[i] ^ B[i] ^ carry;
        carry = (A[i] & B[i]) | (A[i] & carry) | (B[i] & carry);
    }
    return SUM;
}

template<size_t size>
bitset<size> operator-(bitset<size> &A, bitset<size> &B) noexcept {
    bitset<size> diff, B_c, one = 1;
    for (int i = 0; i < size; i++)
        B_c[i] = 1;
    B = B ^ B_c;
    diff = A + B;
    diff = diff + one;
    return diff;
}

void KCipher::init(bitset<K> key) {
    KeyExpansion(key, round_keys);
}

bitset<N> KCipher::BitReordering(bitset<N> input, int index) {
    bitset<N> output;
    for (int i = 0; i < N; i++) {
        int new_index = reordering_24[index][i];
        output[new_index] = input[i];
    }
    return output;
}

bitset<N> KCipher::BitReorderingRev(bitset<N> input, int index) {
    bitset<N> output;
    for (int i = 0; i < N; i++) {
        int new_index = rev_reordering_24[index][i];
        output[new_index] = input[i];
    }
    return output;
}

bitset<N> KCipher::SBox(bitset<N> input, bitset<N> rand[], int index) {
    bitset<N> output;
    for (int block = 0; block < N; block += M) {
        bitset<M> cur_block, cur_r0, cur_r1;
        long block_val, r0_val, r1_val;
        for (int i = block; i < block + M; i++) {
            cur_block[i - block] = input[i];
            cur_r0[i - block] = rand[2 * index][i];
            cur_r1[i - block] = rand[2 * index + 1][i];
        }
        block_val = cur_block.to_ulong();
        r0_val = cur_r0.to_ulong();
        r1_val = cur_r1.to_ulong();
        uint8_t t = 0;
        if (index != -1) {
            t = sbox[block_val ^ r0_val] + r1_val;
            t = ROTL8(t, 2);
        } else {
            t = sbox[block_val];
            t = ROTL8(t, 2);
        }
        cur_block = t;
        for (int i = block; i < block + M; i++) {
            output[i] = cur_block[i - block];
        }
    }
    return output;
}

bitset<N> KCipher::Inv_SBox(bitset<N> input, bitset<N> rand[], int index) {
    bitset<N> output;
    for (int block = 0; block < N; block += M) {
        bitset<M> cur_block, cur_r0, cur_r1;
        long block_val, r0_val, r1_val;
        for (int i = block; i < block + M; i++) {
            cur_block[i - block] = input[i];
            cur_r0[i - block] = rand[2 * index][i];
            cur_r1[i - block] = rand[2 * index + 1][i];
        }
        block_val = cur_block.to_ulong();
        r0_val = cur_r0.to_ulong();
        r1_val = cur_r1.to_ulong();
        uint8_t t = block_val;
        t = ROTR8(t, 2);
        if (index != -1) {
            t -= r1_val;
            t = sbox_inv[t] ^ r0_val;
        } else {
            t = sbox_inv[t];
        }
        cur_block = t;
        for (int i = block; i < block + M; i++) {
            output[i] = cur_block[i - block];
        }
    }
    return output;
}

bitset<N> KCipher::EncCPA(bitset<N> input, bitset<K> key, bitset<N> rand[]) {
    // modular addition with constant c_0 is ignored because it does not contribute to security.
    for (int i = 0; i < 3; i++) {
        input = input + round_keys[i];
        input = BitReordering(input, i);
        input = SBox(input, rand, i);
    }
    bitset<N> veil = BitReordering(round_keys[2], 3);
    return input ^ veil;
}

bitset<N> KCipher::DecCPA(bitset<N> input, bitset<K> key, bitset<N> rand[]) {
    bitset<N> veil = BitReordering(round_keys[2], 3);
    input = input ^ veil;
    for (int i = 0; i < 3; i++) {
        input = Inv_SBox(input, rand, 2 - i);
        input = BitReordering(input, 12 - i);
        input = input - round_keys[2 - i];
    }
    return input;
}

void KCipher::KeyExpansion(bitset<K> key, bitset<N> K[]) {
    if (N < 33) {
        for (int i = 0; i < 3; i++) {
            for (int j = i * N; j < (i + 1) * N; j++) {
                K[i][j - i * N] = key[j];
            }
        }
    } else {
        bitset<N> C, U, rand[4];
        bitset<64> t[2];
        t[0] = __kcipher_range_65_128_const_1[0];
        t[1] = __kcipher_range_65_128_const_1[1];
        for (int j = 0; j < 128; j++)
            C[j] = j < 64 ? t[0][j] : t[1][j - 64];
        bitset<N> temp_key;
        for(uint16_t i = 0; i < N; i++)
            temp_key[i] = key[i];
        K[0] = temp_key;
        U = C + temp_key;
        U = BitReordering(U, 4);
        U = SBox(U, rand, -1);
        K[1] = BitReordering(U, 5);
        t[0] = __kcipher_range_65_128_const_2[0];
        t[1] = __kcipher_range_65_128_const_2[1];
        for (int j = 0; j < 128; j++)
            C[j] = j < 64 ? t[0][j] : t[1][j - 64];
        U = C + K[1];
        U = BitReordering(U, 6);
        U = SBox(U, rand, -1);
        K[2] = BitReordering(U, 7);
    }

}

void KCipher::KeyRecover(bitset<N> key, bitset<N> K[]) {
    bitset<N> C, U, rand[4];
    bitset<64> t[2];
    K[2] = BitReorderingRev(key, 3);

    t[0] = __kcipher_range_65_128_const_2[0];
    t[1] = __kcipher_range_65_128_const_2[1];
    for (int j = 0; j < 128; j++)
        C[j] = j < 64 ? t[0][j] : t[1][j - 64];
    K[1] = BitReorderingRev(K[2], 7);
    K[1] = Inv_SBox(K[1], rand, -1);
    K[1] = BitReorderingRev(K[1], 6);
    K[1] = K[1] - C;

    t[0] = __kcipher_range_65_128_const_1[0];
    t[1] = __kcipher_range_65_128_const_1[1];
    for (int j = 0; j < 128; j++)
        C[j] = j < 64 ? t[0][j] : t[1][j - 64];
    K[0] = BitReorderingRev(K[1], 5);
    K[0] = Inv_SBox(K[0], rand, -1);
    K[0] = BitReorderingRev(K[0], 4);
    K[0] = K[0] - C;
}
