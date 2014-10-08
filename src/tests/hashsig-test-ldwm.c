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

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashsig.h"
#include "ldwm_defs.h"


/* Test program */

#include <sodium.h>

void dump_hex (const uint8_t *buf, const size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
    printf("%02x", buf[i]);
  printf("\n");
}

int main (int argc, char *argv[])
{
  hashsig_t *ctx;

  size_t idx;
  uint8_t bit;
  long tests = 1;

  uint8_t priv[LDWM_SIG_LEN];
  uint8_t pub[LDWM_N];
  uint8_t sig[LDWM_SIG_LEN];

  uint8_t *msg;
  uint16_t m_len;

  if (argc == 2)
    tests = atol(argv[1]);

  randombytes_salsa20_random_buf(&m_len, 2);
  msg = calloc(1, m_len);
  randombytes_salsa20_random_buf(msg, m_len);

  randombytes_salsa20_random_buf(priv, LDWM_SIG_LEN);
  memcpy(sig, priv, LDWM_SIG_LEN);
  ctx = hashsig_create_context(priv, LDWM_SIG_LEN, NULL);


  printf("Message: ");
  dump_hex(msg, m_len);
  printf("Private key: ");
  dump_hex(priv, LDWM_SIG_LEN);

  hashsig_ldwm_public_key(ctx, priv, pub);
  hashsig_ldwm_sign(ctx, sig, msg, m_len, 0);

  printf("Public key: ");
  dump_hex(pub, LDWM_N);
  printf("Signature: ");
  dump_hex(sig, LDWM_SIG_LEN);

  printf("\n");

  /* Check positive case. */
  if (!hashsig_ldwm_verify(ctx, pub, sig, msg, m_len, 0))
    printf("Successfully signed and verified good message.\n");
  else
    printf("Failure verifying good message.\n");

  /* Apply various random corruptions and check for failure. */
  for (; tests; tests--)
  {
    if (m_len)
    {
      idx = randombytes_salsa20_random_uniform(m_len);
      bit = 1 << randombytes_salsa20_random_uniform(8);
      msg[idx] ^= bit;
      if (hashsig_ldwm_verify(ctx, pub, sig, msg, m_len, 0))
        printf("Successfully failed verification of bad message.\n");
      else
        printf("Failure at detecting bad message.\n");
      msg[idx] ^= bit;
    }

    idx = randombytes_salsa20_random_uniform(LDWM_N);
    bit = 1 << randombytes_salsa20_random_uniform(8);
    pub[idx] ^= bit;
    if (hashsig_ldwm_verify(ctx, pub, sig, msg, m_len, 0))
      printf("Successfully failed verification with bad public key.\n");
    else
      printf("Failure at detecting bad public key.\n");
    pub[idx] ^= bit;

    idx = randombytes_salsa20_random_uniform(LDWM_SIG_LEN);
    bit = 1 << randombytes_salsa20_random_uniform(8);
    sig[idx] ^= bit;
    if (hashsig_ldwm_verify(ctx, pub, sig, msg, m_len, 0))
      printf("Successfully failed verification with bad signature.\n");
    else
      printf("Failure at detecting bad signature.\n");
    sig[idx] ^= bit;
  }

  return 0;
}
