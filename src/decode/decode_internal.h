/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include "types.h"
#include "utilities.h"

// Rotate right the first R_BITS of a syndrome.
// At input, the syndrome is stored as three R_BITS triplicate.
// (this makes rotation easier to implement)
// For the output: the output syndrome has only one R_BITS rotation, the remaining
// (2 * R_BITS) bits are undefined.
EXPAND_FUNC_DECL(rotate_right, OUT syndrome_t *out,
                       IN const syndrome_t *in,
                       IN uint32_t          bitscount)
_INLINE_ void rotate_right(OUT syndrome_t *out,
                       IN const syndrome_t *in,
                       IN uint32_t          bitscount)
{
  SELECT_FUNC(rotate_right, out, in, bitscount);
}

// Duplicates the first R_BITS of the syndrome three times
EXPAND_FUNC_DECL(dup, IN OUT syndrome_t *s)
_INLINE_ void dup(IN OUT syndrome_t *s)
{
  SELECT_FUNC(dup, s);
}

EXPAND_FUNC_DECL(bit_sliced_adder, OUT upc_t *upc,
                                   IN OUT syndrome_t *rotated_syndrome,
                                   IN const size_t    num_of_slices)
_INLINE_ void bit_sliced_adder(OUT upc_t *upc,
                             IN OUT syndrome_t *rotated_syndrome,
                             IN const size_t    num_of_slices)
{
  SELECT_FUNC(bit_sliced_adder, upc, rotated_syndrome, num_of_slices);
}

EXPAND_FUNC_DECL(bit_slice_full_subtract, OUT upc_t *upc, IN uint8_t val)
_INLINE_ void bit_slice_full_subtract(OUT upc_t *upc, IN uint8_t val)
{
  SELECT_FUNC(bit_slice_full_subtract, upc, val);
}
