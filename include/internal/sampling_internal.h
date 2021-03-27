/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include "cpu_features.h"
#include "defs.h"
#include "types.h"
#include <stdio.h>

void secure_set_bits_port(OUT pad_r_t *r,
                          IN size_t    first_pos,
                          IN const idx_t *wlist,
                          IN size_t       w_size);

#if defined(X86_64)
void secure_set_bits_avx2(OUT pad_r_t *r,
                          IN size_t    first_pos,
                          IN const idx_t *wlist,
                          IN size_t       w_size);

void secure_set_bits_avx512(OUT pad_r_t *r,
                            IN size_t    first_pos,
                            IN const idx_t *wlist,
                            IN size_t       w_size);
#endif

// When "a" is considered as part of some larger array, then a_first_pos
// is the start position of "a" in the large array.
_INLINE_ void secure_set_bits(OUT pad_r_t *r,
                              IN size_t    first_pos,
                              IN const idx_t *wlist,
                              IN size_t       w_size)
{
#if defined(X86_64)
  if (is_avx512_enabled())
  {
    secure_set_bits_avx512(r, first_pos, wlist, w_size);
  }
  else if (is_avx2_enabled())
  {
    secure_set_bits_avx2(r, first_pos, wlist, w_size);
  }
  else
#endif
  {
    secure_set_bits_port(r, first_pos, wlist, w_size);
  }
}
