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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "brg_endian.h"
#include "hashsig_defs.h"
#include "hashsig.h"

/* Failing calloc. */
void *hashsig_calloc (size_t nmemb, size_t size)
{
  uint8_t *buf = calloc(nmemb, size);
  if (buf == NULL)
  {
    fprintf(stderr, "Failed to allocate memory.");
    abort();
  }
  return buf;
}

void hashsig_free (void *buf)
{
  free(buf);
}

uint16_t hashsig_load_le16 (const uint8_t *buf)
{
#if PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN || PLATFORM_MUST_ALIGN
  return buf[0] + (uint16_t)(buf[1] << 8);
#else
  return *(uint16_t *)buf;
#endif
}

uint32_t hashsig_load_le32 (const uint8_t *buf)
{
#if PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN || PLATFORM_MUST_ALIGN
  return (hashsig_load_le16(buf) + ((uint32_t)hashsig_load_le16(buf + 2) << 16));
#else
  return *(uint32_t *)buf;
#endif
}

uint64_t hashsig_load_le64 (const uint8_t *buf)
{
#if PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN || PLATFORM_MUST_ALIGN
  return (hashsig_load_le32(buf) + ((uint64_t)hashsig_load_le32(buf + 4) << 32));
#else
  return *(uint64_t *)buf;
#endif
}

void hashsig_store_le16 (uint8_t *buf, uint16_t v)
{
#if PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN || PLATFORM_MUST_ALIGN
  buf[0] = v & 0xff;
  buf[1] = v >> 8;
#else
  memcpy(buf, &v, 2);
#endif
}

void hashsig_store_le32 (uint8_t *buf, uint32_t v)
{
#if PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN || PLATFORM_MUST_ALIGN
  hashsig_store_le16(buf, v & 0xffff);
  hashsig_store_le16(buf + 2, v >> 16);
#else
  memcpy(buf, &v, 4);
#endif
}

void hashsig_store_le64 (uint8_t *buf, uint64_t v)
{
#if PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN || PLATFORM_MUST_ALIGN
  hashsig_store_le32(buf, v & 0xffffffff);
  hashsig_store_le32(buf + 4, v >> 32);
#else
  memcpy(buf, &v, 8);
#endif
}

void hashsig_assert_ctx (hashsig_t *ctx)
{
  assert(ctx != NULL);
  assert(ctx->pub != NULL);
  assert(ctx->keccak_ctx != NULL);
  assert(ctx->priv_scratch != NULL);
  assert(ctx->pub_scratch != NULL);
}
