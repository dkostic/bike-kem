/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include "types.h"
#include "utilities.h"

// c = a+b mod (x^r - 1)
void gf2x_mod_add_avx2(OUT pad_r_t *c, IN const pad_r_t *a, IN const pad_r_t *b);
void gf2x_mod_add_avx512(OUT pad_r_t *c,
                         IN const pad_r_t *a,
                         IN const pad_r_t *b);
void gf2x_mod_add_portable(OUT pad_r_t *c,
                           IN const pad_r_t *a,
                           IN const pad_r_t *b);

_INLINE_ void
gf2x_mod_add(OUT pad_r_t *c, IN const pad_r_t *a, IN const pad_r_t *b)
{
  SELECT_FUNC(gf2x_mod_add, c, a, b);
}

// c = a*b mod (x^r - 1)
void gf2x_mod_mul(OUT pad_r_t *c, IN const pad_r_t *a, IN const pad_r_t *b);

// c = a^-1 mod (x^r - 1)
void gf2x_mod_inv(OUT pad_r_t *c, IN const pad_r_t *a);
