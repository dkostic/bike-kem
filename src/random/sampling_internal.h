/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include "types.h"
#include "utilities.h"

// When "a" is considered as part of some larger array, then a_first_pos
// is the start position of "a" in the large array.
EXPAND_FUNC_DECL(secure_set_bits, OUT pad_r_t *r,
                                  IN size_t    first_pos,
                                  IN const idx_t *wlist,
                                  IN size_t       w_size)

_INLINE_ void secure_set_bits(OUT pad_r_t *   r,
                              IN const size_t first_pos,
                              IN const idx_t *wlist,
                              IN const size_t w_size)
{
  SELECT_FUNC(secure_set_bits, r, first_pos, wlist, w_size);
}
