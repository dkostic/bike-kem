/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#include "types.h"

// Duplicates the first R_BITS of the syndrome three times
// |------------------------------------------|
// |  Third copy | Second copy | first R_BITS |
// |------------------------------------------|
// This is required by the rotate functions.
_INLINE_ void _dup(IN OUT syndrome_t *s)
{
  s->qw[R_QWORDS - 1] =
    (s->qw[0] << LAST_R_QWORD_LEAD) | (s->qw[R_QWORDS - 1] & LAST_R_QWORD_MASK);

  for(size_t i = 0; i < (2 * R_QWORDS) - 1; i++) {
    s->qw[R_QWORDS + i] =
      (s->qw[i] >> LAST_R_QWORD_TRAIL) | (s->qw[i + 1] << LAST_R_QWORD_LEAD);
  }
}

// Use half-adder as described in [5].
_INLINE_ void _bit_sliced_adder(OUT upc_t *upc,
                               IN OUT syndrome_t *rotated_syndrome,
                               IN const size_t    num_of_slices)
{
  // From cache-memory perspective this loop should be the outside loop
  for(size_t j = 0; j < num_of_slices; j++) {
    for(size_t i = 0; i < R_QWORDS; i++) {
      const uint64_t carry = (upc->slice[j].u.qw[i] & rotated_syndrome->qw[i]);
      upc->slice[j].u.qw[i] ^= rotated_syndrome->qw[i];
      rotated_syndrome->qw[i] = carry;
    }
  }
}

_INLINE_ void _bit_slice_full_subtract(OUT upc_t *upc, IN uint8_t val)
{
  // Borrow
  uint64_t br[R_QWORDS] = {0};

  for(size_t j = 0; j < SLICES; j++) {

    const uint64_t lsb_mask = 0 - (val & 0x1);
    val >>= 1;

    // Perform a - b with c as the input/output carry
    // br = 0 0 0 0 1 1 1 1
    // a  = 0 0 1 1 0 0 1 1
    // b  = 0 1 0 1 0 1 0 1
    // -------------------
    // o  = 0 1 1 0 0 1 1 1
    // c  = 0 1 0 0 1 1 0 1
    //
    // o  = a^b^c
    //            _     __    _ _   _ _     _
    // br = abc + abc + abc + abc = abc + ((a+b))c

    for(size_t i = 0; i < R_QWORDS; i++) {
      const uint64_t a      = upc->slice[j].u.qw[i];
      const uint64_t b      = lsb_mask;
      const uint64_t tmp    = ((~a) & b & (~br[i])) | ((((~a) | b) & br[i]));
      upc->slice[j].u.qw[i] = a ^ b ^ br[i];
      br[i]                 = tmp;
    }
  }
}
