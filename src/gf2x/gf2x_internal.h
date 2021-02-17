/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

// For size_t
#include <stdlib.h>

#include "types.h"
#include "utilities.h"

// The size in quadwords of the operands in the gf2x_mul_base function
// for different implementations.
#define GF2X_BASE_QWORDS_PCLMUL   (8)
#define GF2X_BASE_QWORDS_VPCLMUL  (16)
#define GF2X_BASE_QWORDS_PORTABLE (1)

// GF2X multiplication of a and b of size GF2X_BASE_QWORDS, c = a * b
void gf2x_mul_base_pclmul(OUT uint64_t *c,
                          IN const uint64_t *a,
                          IN const uint64_t *b);
void gf2x_mul_base_vpclmul(OUT uint64_t *c,
                           IN const uint64_t *a,
                           IN const uint64_t *b);
void gf2x_mul_base_portable(OUT uint64_t *c,
                            IN const uint64_t *a,
                            IN const uint64_t *b);

// c = a^2
void gf2x_sqr_pclmul(OUT dbl_pad_r_t *c, IN const pad_r_t *a);
void gf2x_sqr_vpclmul(OUT dbl_pad_r_t *c, IN const pad_r_t *a);
void gf2x_sqr_portable(OUT dbl_pad_r_t *c, IN const pad_r_t *a);

// a = a^2 mod (x^r - 1)
void gf2x_mod_sqr_in_place(IN OUT pad_r_t *a, OUT dbl_pad_r_t *secure_buffer);

// The k-squaring function computes c = a^(2^k) % (x^r - 1),
// It is required by inversion, where l_param is derived from k.
EXPAND_FUNC_DECL(k_squaring, OUT pad_r_t *c, IN const pad_r_t *a, IN size_t l_param)
_INLINE_ void k_squaring(OUT pad_r_t *c, IN const pad_r_t *a, IN size_t l_param)
{
  SELECT_FUNC(k_squaring, c, a, l_param);
}

// TODO: add comments
EXPAND_FUNC_DECL(karatzuba_add1, OUT uint64_t *alah,
                                 OUT uint64_t *blbh,
                                 IN const uint64_t *a,
                                 IN const uint64_t *b,
                                 IN size_t          qwords_len)
_INLINE_ void karatzuba_add1(OUT uint64_t *alah,
                           OUT uint64_t *blbh,
                           IN const uint64_t *a,
                           IN const uint64_t *b,
                           IN size_t          qwords_len)
{
  SELECT_FUNC(karatzuba_add1, alah, blbh, a, b, qwords_len);
}

EXPAND_FUNC_DECL(karatzuba_add2, OUT uint64_t *z,
                                 IN const uint64_t *x,
                                 IN const uint64_t *y,
                                 IN size_t          qwords_len)
_INLINE_ void karatzuba_add2(OUT uint64_t *z,
                    IN const uint64_t *x,
                    IN const uint64_t *y,
                           IN size_t          qwords_len)
{
  SELECT_FUNC(karatzuba_add2, z, x, y, qwords_len);
}

EXPAND_FUNC_DECL(karatzuba_add3, OUT uint64_t *c,
                                 IN const uint64_t *mid,
                                 IN size_t          qwords_len)
_INLINE_ void karatzuba_add3(OUT uint64_t *c,
                           IN const uint64_t *mid,
                           IN size_t          qwords_len)
{
  SELECT_FUNC(karatzuba_add3, c, mid, qwords_len);
}

EXPAND_FUNC_DECL(gf2x_red, OUT pad_r_t *c, IN const dbl_pad_r_t *a)
_INLINE_ void gf2x_red(OUT pad_r_t *c, IN const dbl_pad_r_t *a)
{
  SELECT_FUNC(gf2x_red, c, a);
}

