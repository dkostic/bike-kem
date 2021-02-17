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

#pragma once

#include <stdint.h>

#include "defs.h"

#if defined(AVX2)
static uint8_t avx2_flag = 1;
#else
static uint8_t avx2_flag    = 0;
#endif

#if defined(AVX512)
static uint8_t avx512_flag = 1;
#else
static uint8_t avx512_flag  = 0;
#endif

#if defined(PCLMUL)
static uint8_t pclmul_flag = 1;
#else
static uint8_t pclmul_flag  = 0;
#endif

#if defined(VPCLMUL)
static uint8_t vpclmul_flag = 1;
#else
static uint8_t vpclmul_flag = 0;
#endif

_INLINE_ uint8_t is_avx2_enabled() { return avx2_flag; }

_INLINE_ uint8_t is_avx512_enabled() { return avx512_flag; }

_INLINE_ uint8_t is_pclmul_enabled() { return pclmul_flag; }

_INLINE_ uint8_t is_vpclmul_enabled() { return vpclmul_flag; }
