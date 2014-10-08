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

  uint8_t mfs_priv[32];
  hashsig_pub_t *mfs_pub;
  hashsig_sig_t *mfs_sig;
  uint8_t *mfs_pub_buf;
  uint8_t *mfs_sig_buf;

  uint8_t *msg;
  uint16_t m_len;

  if (argc == 2)
    tests = atol(argv[1]);

  /* Generate message and key pair. */
  randombytes_salsa20_random_buf(&m_len, 2);
  msg = calloc(m_len + 0xffff, 1);
  randombytes_salsa20_random_buf(msg, m_len);
  randombytes_salsa20_random_buf(mfs_priv, sizeof(mfs_priv));

  ctx = hashsig_create_context(mfs_priv, 32, NULL);
  mfs_pub = hashsig_get_public_key(ctx);
  mfs_pub_buf = calloc(1, hashsig_public_key_length(ctx));
  mfs_sig_buf = calloc(1, hashsig_signature_length(ctx));

  printf("Message: ");
  dump_hex(msg, m_len);
  printf("Private key: ");
  dump_hex(mfs_priv, hashsig_private_key_length());
  printf("Public key: ");
  hashsig_pub2buf(mfs_pub, mfs_pub_buf, hashsig_public_key_length(ctx));
  dump_hex(mfs_pub_buf, hashsig_public_key_length(ctx));

  /* Sign. */
  mfs_sig = hashsig_sign(ctx, msg, m_len);
  hashsig_sig2buf(mfs_sig, mfs_sig_buf, hashsig_signature_length(ctx));

  printf("Signature: ");
  dump_hex(mfs_sig_buf, hashsig_signature_length(ctx));

  printf("\n");

  /* Check positive case. */
  if (!hashsig_verify(mfs_pub, mfs_sig, msg, m_len))
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
      if (hashsig_verify(mfs_pub, mfs_sig, msg, m_len) > 0)
        printf("Successfully failed verification of bad message.\n");
      else
        printf("Failure at detecting bad message.\n");
      msg[idx] ^= bit;

      idx = randombytes_salsa20_random_uniform(m_len - 1);
      if (hashsig_verify(mfs_pub, mfs_sig, msg, idx) > 0)
        printf("Successfully failed verification of truncated message.\n");
      else
        printf("Failure at detecting truncated message.\n");
    }

    idx = m_len + randombytes_salsa20_random_uniform(0xfffe) + 1;
    if (hashsig_verify(mfs_pub, mfs_sig, msg, idx) > 0)
      printf("Successfully failed verification of appended message.\n");
    else
      printf("Failure at detecting appended message.\n");

    idx = randombytes_salsa20_random_uniform(hashsig_public_key_length(ctx) - 1) + 1;
    bit = 1 << randombytes_salsa20_random_uniform(8);
    mfs_pub_buf[idx] ^= bit;
    hashsig_free(mfs_pub);
    hashsig_buf2pub(&mfs_pub, mfs_pub_buf, hashsig_public_key_length(ctx));
    if (hashsig_verify(mfs_pub, mfs_sig, msg, m_len) > 0)
      printf("Successfully failed verification with bad public key.\n");
    else
      printf("Failure at detecting bad public key.\n");
    mfs_pub_buf[idx] ^= bit;
    hashsig_free(mfs_pub);
    hashsig_buf2pub(&mfs_pub, mfs_pub_buf, hashsig_public_key_length(ctx));

    idx = randombytes_salsa20_random_uniform(hashsig_signature_length(ctx));
    bit = 1 << randombytes_salsa20_random_uniform(8);
    mfs_sig_buf[idx] ^= bit;
    hashsig_free(mfs_sig);
    hashsig_buf2sig(&mfs_sig, mfs_sig_buf, hashsig_signature_length(ctx));
    if (hashsig_verify(mfs_pub, mfs_sig, msg, m_len))
      printf("Successfully failed verification with bad signature.\n");
    else
      printf("Failure at detecting bad signature.\n");
    mfs_sig_buf[idx] ^= bit;
    hashsig_free(mfs_sig);
    hashsig_buf2sig(&mfs_sig, mfs_sig_buf, hashsig_signature_length(ctx));
  }

  return 0;
}
