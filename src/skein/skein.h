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

#ifndef SKEIN_H
#define SKEIN_H

#include <stdint.h>

#define  SKEIN_MODIFIER_WORDS  ( 2) /* Number of modifier (tweak) words. */
#define  SKEIN1024_STATE_WORDS (16)
#define  SKEIN_MAX_STATE_WORDS (16)
#define  SKEIN1024_STATE_BYTES ( 8*SKEIN1024_STATE_WORDS)
#define  SKEIN1024_STATE_BITS  (64*SKEIN1024_STATE_WORDS)
#define  SKEIN1024_BLOCK_BYTES ( 8*SKEIN1024_STATE_WORDS)

/* 1024-bit Skein hash context structure. */
typedef struct
{
  size_t hashBitLen;                 /* Size of hash result, in bits.          */
  size_t bCnt;                       /* Current byte count in buffer b[].      */
  uint64_t T[SKEIN_MODIFIER_WORDS];  /* Tweak words: T[0]=byte cnt, T[1]=flags */
  uint64_t X[SKEIN1024_STATE_WORDS]; /* Chaining variables.                    */
  uint8_t b[SKEIN1024_BLOCK_BYTES];  /* Partial block buffer (8-byte aligned). */
} skein1024_ctx_t;

/* Tweak word T[1]: block type field. */
#define SKEIN_BLK_TYPE_KEY      ( 0)  /* Key, for MAC and KDF.                       */
#define SKEIN_BLK_TYPE_CFG      ( 4)  /* Configuration block.                        */
#define SKEIN_BLK_TYPE_PERS     ( 8)  /* Personalization string.                     */
#define SKEIN_BLK_TYPE_PK       (12)  /* Public key (for digital signature hashing). */
#define SKEIN_BLK_TYPE_KDF      (16)  /* Key identifier for KDF.                     */
#define SKEIN_BLK_TYPE_NONCE    (20)  /* Nonce for PRNG.                             */
#define SKEIN_BLK_TYPE_MSG      (48)  /* Message processing.                         */
#define SKEIN_BLK_TYPE_OUT      (63)  /* Output stage.                               */
#define SKEIN_BLK_TYPE_MASK     (63)  /* Bit field mask.                             */

typedef struct
{
  int last;            /* Array of blocks ends with this one.                            */
  int processed;       /* Block is already processed.                                    */
  int type;            /* Type of block.                                                 */
  const uint8_t *data; /* Data going into block. Ignored for type == CFG and type > MSG. */
  size_t len;          /* Length of data.                                                */
} skein1024_block_t;

void hashsig_skein1024_prepare_hash (skein1024_ctx_t *ctx, size_t len, const uint8_t *nonce, size_t nonce_len);
void hashsig_skein1024_hash (skein1024_ctx_t *prepared, uint8_t *out, const uint8_t *msg, size_t msg_len);

void hashsig_skein1024_sighash (uint8_t *out, size_t len, const uint8_t *pub, size_t pub_len, const uint8_t *msg, size_t msg_len);

/* After this call secret state will be left in the context. Make sure to use the context for something else after use. */
void hashsig_skein1024_stream (skein1024_ctx_t *ctx, uint8_t *out, size_t len, const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len);

/* Warning: Do not use, unless you know what you are doing. */
void hashsig_skein1024_full (size_t hash_bits, skein1024_ctx_t *ctx, uint8_t *out, skein1024_block_t blocks[]);

#endif /* SKEIN_H */
