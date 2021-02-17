/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 *
 * The k-squaring algorithm in this file is based on:
 * [1] Nir Drucker, Shay Gueron, and Dusan Kostic. 2020. "Fast polynomial
 * inversion for post quantum QC-MDPC cryptography". Cryptology ePrint Archive,
 * 2020. https://eprint.iacr.org/2020/298.pdf
 */

#include <assert.h>

#include "cleanup.h"
#include "gf2x_internal.h"
#include "utilities.h"
#include "x86_64_intrinsic.h"

#include "gf2x_helper_common.c"

#define BITS_IN_BYTE (8)

// The k-squaring function computes c = a^(2^k) % (x^r - 1),
// By [1](Observation 1), if
//     a = sum_{j in supp(a)} x^j,
// then
//     a^(2^k) % (x^r - 1) = sum_{j in supp(a)} x^((j * 2^k) % r).
// Therefore, k-squaring can be computed as permutation of the bits of "a":
//     pi0 : j --> (j * 2^k) % r.
// For improved performance, we compute the result by inverted permutation pi1:
//     pi1 : (j * 2^-k) % r --> j.
// Input argument l_param is defined as the value (2^-k) % r.
void k_squaring_portable(OUT pad_r_t *c,
                         IN const pad_r_t *a,
                         IN const size_t   l_param)
{
  bike_memset(c->val.raw, 0, sizeof(c->val));

  // Compute the result byte by byte
  size_t idx = 0;
  for(size_t i = 0; i < R_BYTES; i++) {
    for(size_t j = 0; j < BITS_IN_BYTE; j++, idx++) {
      // Bit of "c" at position idx is set to the value of
      // the bit of "a" at position pi1(idx) = (l_param * idx) % R_BITS.
      size_t pos = (l_param * idx) % R_BITS;

      size_t  pos_byte = pos >> 3;
      size_t  pos_bit  = pos & 7;
      uint8_t bit      = (a->val.raw[pos_byte] >> pos_bit) & 1;

      c->val.raw[i] |= (bit << j);
    }
  }
  c->val.raw[R_BYTES - 1] &= LAST_R_BYTE_MASK;
}

// TODO: add comment
void karatzuba_add1_portable(OUT uint64_t *alah,
                         OUT uint64_t *blbh,
                         IN const uint64_t *a,
                         IN const uint64_t *b,
                         IN const size_t    qwords_len)
{
  _karatzuba_add1(alah, blbh, a, b, qwords_len);
}

void karatzuba_add2_portable(OUT uint64_t *z,
                         IN const uint64_t *x,
                         IN const uint64_t *y,
                         IN const size_t    qwords_len)
{
  _karatzuba_add2(z, x, y, qwords_len);
}

void karatzuba_add3_portable(OUT uint64_t *c,
                         IN const uint64_t *mid,
                         IN const size_t    qwords_len)
{
  _karatzuba_add3(c, mid, qwords_len);
}

// c = a mod (x^r - 1)
void gf2x_red_portable(OUT pad_r_t *c, IN const dbl_pad_r_t *a)
{
  _gf2x_red(c, a);
}

void gf2x_mod_add_portable(OUT pad_r_t *c, IN const pad_r_t *a, IN const pad_r_t *b)
{
  _gf2x_mod_add(c, a, b);
}
