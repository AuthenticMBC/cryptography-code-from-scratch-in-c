#ifndef GF_2_MULT_MODE_H
#define GF_2_MULT_MODE_H

#include <stdio.h>
#include <stdint.h>

// Program for GF(2^8) multiplication with modulo reduction

uint8_t GF_2_mult_mod(uint8_t a, uint8_t b)
{
    // output result
    uint8_t res = 0x00;
    // AES irreducible polynomial without the x^8 bit set
    uint8_t irr_poly = 0x1B;
    // Only set the 8th bit (will be used for checking if the 8th bit of other variable is set) 
    uint8_t checker = 0x80;

    while (a != 0) {
        // Check if the LSB of a is set
        if ((a & 1) == 1) {
            // XOR the result with b
            res ^= b;
        }
        // shift a to the right
        a >>= 1;

        // check if b will exceed the max degree (x^7) if we perform a left shift in GF(2^8)  (means check if MSB of b is set )
        uint8_t overflow = b & checker;

        // shift b to the left
        b <<= 1;

        // the overflow show that b exceeded degree x^7 and reached x^8
        if (overflow) {
            // Add (same as XOR in GF(2^m)) b and the irreducible polynomial
            b ^= irr_poly;
        }
    }

    return res;
}

#endif
