/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include <stdint.h>

void cpu_features_init();

uint32_t is_avx2_enabled();
uint32_t is_avx512_enabled();
uint32_t is_pclmul_enabled();
uint32_t is_vpclmul_enabled();
