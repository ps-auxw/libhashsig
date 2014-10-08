/******************************************************************************
 * libhashsig - A hash-based digital signature library
 *
 * Copyright (c) 2014, Arne Bochem
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the library nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *****************************************************************************/

#ifndef LDWM_DEFS_H
#define LDWM_DEFS_H

#include <stdint.h>
#include "hashsig_defs.h"
#include "hashsig.h"
#include "KeccakHash.h"

/*
   Fixed up but sparse table:
   +--------------------+--------+-----------+----+----+---+-----+----+
   | Name               | H      | F         | m  | n  | w | p   | ls |
   +--------------------+--------+-----------+----+----+---+-----+----+
   | LDWM_SHA512_M64_W8 | SHA512 | SHA512    | 64 | 64 | 8 | 66  | 0  |
   | LDWM_SHA256_M32_W8 | SHA256 | SHA256    | 32 | 32 | 8 | 34  | 0  |
   | LDWM_SHA256_M20_W8 | SHA256 | SHA256-20 | 20 | 32 | 8 | 34  | 0  |
   | LDWM_SHA256_M20_W4 | SHA256 | SHA256-20 | 20 | 32 | 4 | 67  | 4  |
   | LDWM_SHA256_M20_W2 | SHA256 | SHA256-20 | 20 | 32 | 2 | 133 | 6  |
   | LDWM_SHA256_M20_W1 | SHA256 | SHA256-20 | 20 | 32 | 1 | 265 | 7  |
   +--------------------+--------+-----------+----+----+---+-----+----+
*/

#define LDWM_H(output, input, len) hashsig_keccak_hash(ctx->keccak_ctx, output, input, len)
#define LDWM_M 32
#define LDWM_N 32
#define LDWM_W 4
#define LDWM_2_POW_W_MINUS_1 (((uint16_t)1<<LDWM_W)-1)
#define LDWM_SIG_LEN (LDWM_P * LDWM_M)

/*
     u = ceil(8*n/w)
     v = ceil((floor(lg((2^w - 1) * u)) + 1) / w)
     ls = (number of bits in sum) - (v * w)
     p = u + v
*/
#define LDWM_P 67
#define LDWM_LS 4

void hashsig_ldwm_f (hashsig_t *ctx, const int n, uint8_t *buf);
void hashsig_ldwm_public_key (hashsig_t *ctx, uint8_t *priv, uint8_t *pub);
uint16_t hashsig_ldwm_checksum (const uint8_t *hash);
void hashsig_ldwm_sign (hashsig_t *ctx, uint8_t *priv, const uint8_t *message, const size_t len, const int pre_hashed);
int hashsig_ldwm_verify (hashsig_t *ctx, const uint8_t *pub, const uint8_t *sig, const uint8_t *message, const size_t len, const int pre_hashed);

#endif /* LDWM_DEFS_H */
