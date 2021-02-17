/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

// TODO: add comment
_INLINE_ void _karatzuba_add1(OUT uint64_t *alah,
OUT uint64_t *blbh,
IN const uint64_t *a,
IN const uint64_t *b,
IN const size_t    qwords_len)
{
assert(qwords_len % REG_QWORDS == 0);

REG_T va0, va1, vb0, vb1;

for(size_t i = 0; i < qwords_len; i += REG_QWORDS) {
va0 = LOAD(&a[i]);
va1 = LOAD(&a[i + qwords_len]);
vb0 = LOAD(&b[i]);
vb1 = LOAD(&b[i + qwords_len]);

STORE(&alah[i], va0 ^ va1);
STORE(&blbh[i], vb0 ^ vb1);
}
}

_INLINE_ void _karatzuba_add2(OUT uint64_t *z,
IN const uint64_t *x,
IN const uint64_t *y,
IN const size_t    qwords_len)
{
assert(qwords_len % REG_QWORDS == 0);

REG_T vx, vy;

for(size_t i = 0; i < qwords_len; i += REG_QWORDS) {
vx = LOAD(&x[i]);
vy = LOAD(&y[i]);

STORE(&z[i], vx ^ vy);
}
}

_INLINE_ void _karatzuba_add3(OUT uint64_t *c,
IN const uint64_t *mid,
IN const size_t    qwords_len)
{
assert(qwords_len % REG_QWORDS == 0);

REG_T vr0, vr1, vr2, vr3, vt;

uint64_t *c0 = c;
uint64_t *c1 = &c[qwords_len];
uint64_t *c2 = &c[2 * qwords_len];
uint64_t *c3 = &c[3 * qwords_len];

for(size_t i = 0; i < qwords_len; i += REG_QWORDS) {
vr0 = LOAD(&c0[i]);
vr1 = LOAD(&c1[i]);
vr2 = LOAD(&c2[i]);
vr3 = LOAD(&c3[i]);
vt  = LOAD(&mid[i]);

STORE(&c1[i], vt ^ vr0 ^ vr1);
STORE(&c2[i], vt ^ vr2 ^ vr3);
}
}

// c = a mod (x^r - 1)
_INLINE_ void _gf2x_red(OUT pad_r_t *c, IN const dbl_pad_r_t *a)
{
const uint64_t *a64 = (const uint64_t *)a;
uint64_t *      c64 = (uint64_t *)c;

for(size_t i = 0; i < R_QWORDS; i += REG_QWORDS) {
REG_T vt0 = LOAD(&a64[i]);
REG_T vt1 = LOAD(&a64[i + R_QWORDS]);
REG_T vt2 = LOAD(&a64[i + R_QWORDS - 1]);

vt1 = SLLI_I64(vt1, LAST_R_QWORD_TRAIL);
vt2 = SRLI_I64(vt2, LAST_R_QWORD_LEAD);

vt0 ^= (vt1 | vt2);

STORE(&c64[i], vt0);
}

c64[R_QWORDS - 1] &= LAST_R_QWORD_MASK;

// Clean the secrets from the upper part of c
secure_clean((uint8_t *)&c64[R_QWORDS],
(R_PADDED_QWORDS - R_QWORDS) * sizeof(uint64_t));
}

_INLINE_ void _gf2x_mod_add(OUT pad_r_t *c, IN const pad_r_t *a, IN const pad_r_t *b)
{
REG_T           va, vb;
const uint64_t *a_qwords = (const uint64_t *)a;
const uint64_t *b_qwords = (const uint64_t *)b;
uint64_t *      c_qwords = (uint64_t *)c;

for(size_t i = 0; i < R_PADDED_QWORDS; i += REG_QWORDS) {
va = LOAD(&a_qwords[i]);
vb = LOAD(&b_qwords[i]);

STORE(&c_qwords[i], va ^ vb);
}
}
