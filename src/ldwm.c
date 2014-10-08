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

/* Lamport, Diffie, Winternitz and Merkle One-Time Signatures */

#include <string.h>

#include "ldwm_defs.h"
#include "keccak.h"
#include "util.h"

void hashsig_ldwm_f (hashsig_t *ctx, const int n, uint8_t *buf)
{
  uint8_t tmp[LDWM_N];
  int i;

  if (LDWM_M < LDWM_N)
  {
    memcpy(tmp, buf, LDWM_M);
    for (i = 1; i <= n; i++)
      LDWM_H(tmp, tmp, LDWM_M);
    memcpy(buf, tmp, LDWM_M);
  }
  else
    for (i = 1; i <= n; i++)
      LDWM_H(buf, buf, LDWM_M);
}

void hashsig_ldwm_public_key (hashsig_t *ctx, uint8_t *priv, uint8_t *pub)
{
  static const int e = LDWM_2_POW_W_MINUS_1;
  size_t i;

  for (i = 0; i < LDWM_SIG_LEN; i += LDWM_M)
    hashsig_ldwm_f(ctx, e, priv + i);

  LDWM_H(pub, priv, LDWM_SIG_LEN);
}

/* Simple explanation of the checksum:
 *   1) Calculate the difference between the maximum number of times that H is applied, and the number of times it is actually applied in the signature.
 *   2) Encode the checksum using hash chains.
 *   3) If an attacker adds applications of H to other hashes in the signature, sum will decrease and the attacker needs to find pre-images for the hashes encoding the checksum.
 *      Vice versa: If the attacker tries to apply H to hashes encoding the checksum, the attacker needs to find pre-images of other hashes.
 */
uint16_t hashsig_ldwm_checksum (const uint8_t *hash)
{
  static const int e = LDWM_2_POW_W_MINUS_1;
  uint16_t sum = 0;
  size_t i, j;

  for (i = 0; i < LDWM_N; i++)
  {
    uint8_t a = hash[i];

    for (j = 0; j < 8; j += LDWM_W)
    {
      sum += e - (a & e);
      a >>= LDWM_W;
    }
  }

  return (sum << LDWM_LS);
}

void hashsig_ldwm_sign (hashsig_t *ctx, uint8_t *priv, const uint8_t *message, const size_t len, const int pre_hashed)
{
  static const int e = LDWM_2_POW_W_MINUS_1;
  uint8_t v[LDWM_N + 2];
  uint16_t c;
  size_t i, j, m = 0;

  if (pre_hashed)
    memcpy(v, message, LDWM_N);
  else
    LDWM_H(v, message, len);

  c = hashsig_ldwm_checksum(v);
  hashsig_store_le16(v + LDWM_N, c);

  for (i = 0; i < LDWM_P; )
  {
    uint8_t a = v[m++];

    for (j = 0; j < 8 && i < LDWM_P; j += LDWM_W)
    {
      hashsig_ldwm_f(ctx, a & e, priv + i * LDWM_M);

      a >>= LDWM_W;
      i++;
    }
  }
}

int hashsig_ldwm_verify (hashsig_t *ctx, const uint8_t *pub, const uint8_t *sig, const uint8_t *message, const size_t len, const int pre_hashed)
{
  static const int e = LDWM_2_POW_W_MINUS_1;
  uint8_t copy[LDWM_SIG_LEN];
  uint8_t v[LDWM_N + 2];
  uint16_t c;
  size_t i, j, m = 0;

  if (pre_hashed)
    memcpy(v, message, LDWM_N);
  else
    LDWM_H(v, message, len);

  c = hashsig_ldwm_checksum(v);
  v[LDWM_N] = c & 0xff;
  v[LDWM_N + 1] = c >> 8;

  memcpy(copy, sig, LDWM_SIG_LEN);

  for (i = 0; i < LDWM_P; )
  {
    uint8_t a = v[m++];

    for (j = 0; j < 8 && i < LDWM_P; j += LDWM_W)
    {
      hashsig_ldwm_f(ctx, e - (a & e), copy + i * LDWM_M);

      a >>= LDWM_W;
      i++;
    }
  }

  LDWM_H(v, copy, LDWM_SIG_LEN);

  if (memcmp(pub, v, LDWM_N))
    return 1;
  else
    return 0;
}
