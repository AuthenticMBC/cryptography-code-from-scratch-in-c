#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "GF_2_mult_mod.h"

#define KEY_LENGTH 16 // BYTES (8 BITS)
#define W_LENGTH 44 // WORDS (32 BITS)
#define PLAINTEXT_LENGTH 16 // BYTES (8 BITS)
#define BLOCK_LENGTH 16 // BYTES (8 BITS)
#define printbytes(format, expr, len) \
{ \
    for (int i=0; i< len; i++) { \
        fprintf(stdout, format, expr[i]); \
    } \
    fprintf(stdout, "\n"); \
}

#define printsubkeys(W, len) \
{ \
    for (int i=0; i< len; i+= 4) { \
        fprintf(stdout, "subkey %d\t", i / 4); \
        for (int j = i; j < i + 4; j++) { \
            printf("%08X ", W[j]); \
        } \
        fprintf(stdout, "\n"); \
    } \
}

// #define fill(arr, len, value) \
// { \
//     for (int i = 0; i < len; ++i) \
//     { \
//         arr[i] = value; \
//     } \
// }

void copy_org_key_to_w(unsigned char key[], u_int32_t W[])
{
    for (int i = 0; i < 4; i++) {
        int shift = 8 * 3;
        u_int32_t w_temp_res = 0x00000000;
        for (int j = (i * 4); j < (i * 4) + 4; j++) {
            u_int32_t w_temp = key[j];
            w_temp <<= shift;
            w_temp_res ^= w_temp;
            shift -= 8;
        }
        W[i] = w_temp_res;
    }
}

u_int8_t s_box(u_int8_t coord) {
    u_int8_t sbox[16][16] = {
        {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
        {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
        {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
        {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
        {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
        {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
        {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
        {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
        {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
        {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
        {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
        {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
        {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
        {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
        {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
        {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
    };

    return sbox[(coord & 0xF0) >> 4][coord & 0x0F];
}

u_int32_t g(u_int32_t V, uint8_t round_no)
{

    u_int8_t RC[] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };

    u_int8_t V2[4] = { 0x00 };
    u_int32_t temp = V;
    u_int32_t mask = 0x000000FF; // Will helps us to get only the Least Significant Byte via a bitwise AND operation

    /*
        This loop help to break the u_int32_t V into an arr
        ex. 6E65726D --> { 0x6E, 0x65, 0x72, 0x6D }
    */
    for (int i = 3; i >= 0; i--) {
        V2[i] = (temp & mask);
        temp >>= 8;
    }

    // Rotate 
    u_int8_t V_RES[4] = { 0x00 };
    V_RES[0] = V2[1];
    V_RES[1] = V2[2];
    V_RES[2] = V2[3];
    V_RES[3] = V2[0];

    // S-Box
    for (int i = 0; i < 4; i++) {
        V_RES[i] = s_box(V_RES[i]);
    }


    V_RES[0] ^= RC[round_no - 1];

    temp = 0x00;
    u_int32_t res = 0x00;
    int shift = 8 * 3;
    // Combine back the V's to one variable of 32 bits (4 bytes)
    for (int i = 0; i < 4; i++) {
        temp = V_RES[i];
        temp <<= shift;
        res ^= temp;
        shift -= 8;
    }

    return res;
}

void key_schedule(unsigned char key[], u_int32_t W[])
{
    copy_org_key_to_w(key, W);

    for (int i = 1; i <= 10; i++) {
        W[4 * i] = W[4 * (i - 1)] ^ g(W[4 * i - 1], i);
        for (int j = 1; j <= 3; j++) {
            W[4 * i + j] = W[4 * i + j - 1] ^ W[4 * (i - 1) + j];
        }
    }

}



// void set_block(u_int32_t block[], uint8_t plaintext[], int block_no)
// {
//     // block_no 1 | index :  0 - 15
//     // block_no 2 | index : 16 - 31
//     // block_no 3 | index : 32 - 47

//     // i = (block_no-1)*16 
//     // Ex block_no=1, start idx = (1-1)*16 = 0

//     u_int32_t temp1 = 0x00, temp2 = 0x00;
//     int j = 0, shift = 8 * 3;
//     for (int i = (block_no - 1) * 16; i < ((block_no - 1) * 16) + 16; i++) {
//         u_int32_t temp1 = plaintext[i];
//         temp1 <<= shift;
//         shift -= 8;
//         temp2 ^= temp1;
//         if ((i + 1) % 4 == 0) {
//             block[j++] = temp2;
//             temp2 = 0x00;
//             shift = 8 * 3;
//         }
//     }
// }

void key_addition_layer(uint8_t block[], u_int32_t W[], int round_no)
{
    int k = 0;
    for (int i = (4 * round_no); i < (4 * round_no) + 4; i++) {
        // loop again since we have 4 bytes in each W[i] 
        int shifter = 8 * 3;
        for (int j = 0; j < 4; j++) {
            uint8_t temp2 = (W[i] >> shifter) & 0xFF;
            block[k++] ^= temp2;
            shifter -= 8;
        }
    }
}

void byte_substitution_layer(uint8_t block[])
{
    for (int i = 0; i < BLOCK_LENGTH; i++) {
        block[i] = s_box(block[i]);
    }
}

void shiftrows_layer(uint8_t block[])
{
    uint8_t temp1, temp2, temp3;

    // Row 0: no shift

    // Row 1: shift left by 1
    temp1 = block[1];
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = temp1;

    // Row 2: shift left by 2
    temp1 = block[2];
    temp2 = block[6];
    block[2] = block[10];
    block[6] = block[14];
    block[10] = temp1;
    block[14] = temp2;

    // Row 3: shift left by 3
    temp1 = block[3];
    temp2 = block[7];
    temp3 = block[11];
    block[3] = block[15];
    block[7] = temp1;
    block[11] = temp2;
    block[15] = temp3;

}

void matmul(uint8_t C[], uint8_t B[], int sz)
{
    const int msz = 4;
    u_int8_t constant_matrix[msz][msz] = {
           {0x02, 0x03, 0x01, 0x01},
           {0x01, 0x02, 0x03, 0x01},
           {0x01, 0x01, 0x02, 0x03},
           {0x03, 0x01, 0x01, 0x02},
    };

    // u_int8_t C[msz] = { 0 };
    for (int i = 0; i < msz; i++) {
        for (int j = 0; j < msz; j++) {
            u_int8_t ans = GF_2_mult_mod(constant_matrix[i][j], B[j]);
            C[i] ^= ans;
        }
    }

}

void mixcolumn_layer(uint8_t block[])
{
    const int sz = 4;
    for (int i = 0; i < BLOCK_LENGTH; i += 4) {
        int k = 0;
        uint8_t B[sz] = { 0 }, C[sz] = { 0 };

        for (int j = i; j < (i + 4); j++) {
            B[k++] = block[j];
        }

        matmul(C, B, sz);
        // printbytes("%02X ", C, sz);

        k = 0;
        for (int j = i; j < (i + 4); j++) {
            block[j] = C[k++];
        }
    }
}

int main() {
    // unsigned char key[] = {
    //     0x6E, 0x65, 0x72, 0x6D, 0x6F, 0x2D, 0x62, 0x61,
    //     0x73, 0x7A, 0x75, 0x2D, 0x73, 0x61, 0x72, 0x6B
    // };
    uint8_t key[16] = {
        0x2B, 0x7E, 0x15, 0x16,
        0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88,
        0x09, 0xCF, 0x4F, 0x3C
    };
    u_int32_t W[W_LENGTH] = { 0 };
    uint8_t plaintext[] = {
        0x32, 0x43, 0xF6, 0xA8,
        0x88, 0x5A, 0x30, 0x8D,
        0x31, 0x31, 0x98, 0xA2,
        0xE0, 0x37, 0x07, 0x34
    };
    // Key schedule
    key_schedule(key, W);

    printf("key:\t\t");
    printbytes("%02X ", key, KEY_LENGTH);
    printf("plaintext:\t");
    printbytes("%02X ", plaintext, PLAINTEXT_LENGTH);


    // Round 0
    key_addition_layer(plaintext, W, 0);

    // Round 1 to 10
    for (int round_no = 1; round_no <= 10; round_no++) {
        byte_substitution_layer(plaintext);
        shiftrows_layer(plaintext);
        if (round_no != 10) {
            mixcolumn_layer(plaintext);
        }
        key_addition_layer(plaintext, W, round_no);
    }
    printf("Ciphertext:\t");
    printbytes("%02X ", plaintext, PLAINTEXT_LENGTH);

    return 0;
}

