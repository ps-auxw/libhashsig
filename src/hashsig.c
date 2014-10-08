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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "keccak.h"
#include "util.h"
#include "ldwm_defs.h"
#include "lmfs_defs.h"
#include "hashsig_defs.h"
#include "hashsig.h"

/* libhashsig API */

hashsig_t *hashsig_create_context (const uint8_t *const priv, const size_t priv_len, const hashsig_pub_t *pub)
{
  hashsig_t *ctx = hashsig_calloc(1, sizeof(hashsig_t));
  ctx->pub = hashsig_calloc(1, LDWM_N);
  ctx->keccak_ctx = hashsig_calloc(1, sizeof(keccak_ctx_t));
  ctx->priv_scratch = hashsig_calloc(LMFS_LEAVES, LDWM_SIG_LEN);
  ctx->pub_scratch = hashsig_calloc(LMFS_LEAVES, LDWM_N);
  ctx->priv_len = priv_len;
  ctx->type = HASHSIG_TYPE_KECCAK_T32_B8_M32_N32_W4;

  hashsig_assert_ctx(ctx);
  assert(sizeof(ctx->type) == LMFS_SIG_HEADER);
  assert(priv_len >= 32);

  /* Keep around pointer to user's private key buffer. */
  ctx->priv = priv;

  /* Initialize Keccak for good measure. */
  hashsig_keccak_prepare_hash(ctx->keccak_ctx, LDWM_N, NULL, 0);

  /* Calculate or copy public key. */
  if (pub != NULL)
  {
    assert(hashsig_public_key_length(ctx) == pub->len && pub->type == ctx->type);
    memcpy(ctx->pub, pub->data, hashsig_public_key_length(ctx));
  }
  else
    hashsig_lmfs_public_key(ctx, ctx->pub);

  return ctx;
}

hashsig_t *hashsig_create_context_type (const uint32_t type, const uint8_t *const priv, const size_t priv_len, const hashsig_pub_t *pub)
{
  if (type != HASHSIG_TYPE_KECCAK_T32_B8_M32_N32_W4)
    return NULL;
  return hashsig_create_context(priv, priv_len, pub);
}

void hashsig_destroy_context (hashsig_t *ctx)
{
  hashsig_assert_ctx(ctx);
  hashsig_free(ctx->pub);
  hashsig_free(ctx->keccak_ctx);
  hashsig_free(ctx->priv_scratch); /* No need to zero; always overwritten by public key intermediate values. */
  hashsig_free(ctx->pub_scratch);
  hashsig_free(ctx);
}

hashsig_pub_t *hashsig_get_public_key (hashsig_t *ctx)
{
  char *buf;
  hashsig_pub_t *pub;

  hashsig_assert_ctx(ctx);

  buf = hashsig_calloc(1, sizeof(hashsig_pub_t) + hashsig_public_key_length(ctx));
  pub = (hashsig_pub_t *)buf;

  pub->type = ctx->type;
  pub->data = (uint8_t *)buf + sizeof(hashsig_pub_t);
  pub->len = hashsig_public_key_length(ctx);
  memcpy(pub->data, ctx->pub, LDWM_N);

  return pub;
}

hashsig_sig_t *hashsig_sign (hashsig_t *ctx, const uint8_t *message, const size_t len)
{
  char *buf;
  hashsig_sig_t *sig;

  hashsig_assert_ctx(ctx);

  buf = hashsig_calloc(1, sizeof(hashsig_sig_t) + hashsig_signature_length(ctx));
  sig = (hashsig_sig_t *)buf;

  sig->type = ctx->type;
  sig->len = hashsig_signature_length(ctx);
  sig->data = (uint8_t *)buf + sizeof(hashsig_sig_t);

  hashsig_lmfs_sign(ctx, sig->data, message, len);

  return sig;
}

int hashsig_verify (const hashsig_pub_t *pub, const hashsig_sig_t *sig, const uint8_t *message, const size_t len)
{
  uint8_t priv[64] = { 0 };
  hashsig_t *ctx;
  int valid;

  ctx = hashsig_create_context_type(pub->type, priv, sizeof(priv), pub);

  if (!(ctx != NULL && pub->type == sig->type && pub->len == hashsig_public_key_length(ctx) && sig->len == hashsig_signature_length(ctx)))
  {
    hashsig_free(ctx);
    return -1;
  }

  valid = hashsig_lmfs_verify(ctx, pub->data, sig->data, message, len);
  hashsig_destroy_context(ctx);

  return valid;
}

size_t hashsig_pub2buf (const hashsig_pub_t *pub, uint8_t *buf, const size_t len)
{
  if (len < pub->len)
    return pub->len;

  buf[0] = pub->type;
  memcpy(buf + 1, pub->data, pub->len - 1);

  return 0;
}

size_t hashsig_buf2pub (hashsig_pub_t **pub_ptr, const uint8_t *buf, const size_t len)
{
  char *alloc_buf;
  hashsig_pub_t *pub;

  if (len != LDWM_N + 1)
  {
    *pub_ptr = NULL;
    return LDWM_N + 1;
  }

  alloc_buf = hashsig_calloc(1, sizeof(hashsig_pub_t) + len - 1);
  pub = (hashsig_pub_t *)alloc_buf;

  pub->type = buf[0];
  pub->len = len;
  pub->data = (uint8_t *)alloc_buf + sizeof(hashsig_pub_t);
  memcpy(pub->data, buf + 1, len - 1);

  *pub_ptr = pub;
  return 0;
}

size_t hashsig_sig2buf (const hashsig_sig_t *sig, uint8_t *buf, const size_t len)
{
  assert(sig->type == sig->data[0]);

  if (len < sig->len)
    return sig->len;

  memcpy(buf, sig->data, sig->len);

  return 0;
}

size_t hashsig_buf2sig (hashsig_sig_t **sig_ptr, const uint8_t *buf, const size_t len)
{
  char *alloc_buf;
  hashsig_sig_t *sig;

  if (len != LMFS_SIG_LEN)
  {
    *sig_ptr = NULL;
    return LMFS_SIG_LEN;
  }

  alloc_buf = hashsig_calloc(1, sizeof(hashsig_sig_t) + len);
  sig = (hashsig_sig_t *)alloc_buf;

  sig->type = buf[0];
  sig->len = len;
  sig->data = (uint8_t *)alloc_buf + sizeof(hashsig_sig_t);
  memcpy(sig->data, buf, len);

  *sig_ptr = sig;
  return 0;
}

size_t hashsig_private_key_length ()
{
  return 32;
}

size_t hashsig_private_key_length_type (const uint32_t type)
{
  return ((type & 0x08) ? 64 : 32);
}

size_t hashsig_signature_length (const hashsig_t *ctx)
{
  return LMFS_SIG_LEN;
}

size_t hashsig_public_key_length (const hashsig_t *ctx)
{
  return (((ctx->type & 0x08) ? 64 : 32) + 1);
}

int hashsig_object_type (const char *obj_type, const uint8_t type, char *str, const size_t len)
{
  int w      = 1 << (type & 0x03);
  int m_or_t =      (type & 0x04);
  int n      =      (type & 0x08) ? 64 : 32;
  int b      =      (type & 0x10) ? 8 : 16;
  char *algo =      (type & 0x20) ? "Skein" : "Keccak";
  int m, t;
  int ret;

  if (n == 32)
  {
    t = 32;
    if (m_or_t)
      m = 32;
    else
      m = 20;
  }
  else
  {
    m = 64;
    if (m_or_t)
      t = 64;
    else
      t = 32;
  }

  ret = snprintf(str, len, "libhashsig %s (%s T%u B%u M%u N%u W%u)", obj_type, algo, t, b, m, n, w);

  if (ret < 0 || ret >= len)
    return 1;
  return 0;
}

int hashsig_signature_type (const hashsig_sig_t *sig, char *str, const size_t len)
{
  return hashsig_object_type("signature", sig->type, str, len);
}

int hashsig_public_key_type (const hashsig_pub_t *pub, char *str, const size_t len)
{
  return hashsig_object_type("public key", pub->type, str, len);
}
