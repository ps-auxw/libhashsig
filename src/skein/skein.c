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

/* Warning: Comments in this file may not be up to date. */

/****************************************************************************
 *
 * Implementation of the Skein hash function.
 *
 * Based on the public domain reference code written by Doug Whiting, 2008.
 * 
 ****************************************************************************/

#include <string.h>
#include <assert.h>
#include "skein_internal.h"
#include "util.h"

/******************************** Skein1024 *********************************/

/* This implementation only supports 2**64 input bytes (no carry out here). */

/* Definitions used in the Skein1024 block function. */
#define RCNT            (SKEIN1024_ROUNDS_TOTAL / 8)
#define WCNT            (SKEIN1024_STATE_WORDS)
#define BLK_BITS        (WCNT*64)
#define KW_TWK_BASE     (0)
#define KW_KEY_BASE     (3)
#define ks              (kw + KW_KEY_BASE)
#define ts              (kw + KW_TWK_BASE)

void hashsig_skein1024_process_blocks(skein1024_ctx_t *ctx, const uint8_t *blkPtr, size_t blkCnt, size_t byteCntAdd)
{
  uint64_t X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, X12, X13, X14, X15;  /* Local copy of vars, for speed. */
  uint64_t kw[WCNT + 4 + RCNT * 2];        /* Key schedule words: chaining * vars + tweak. */
  uint64_t w[WCNT];                        /* Local copy of input block.                   */
	size_t r;

  /* Never call with blkCnt == 0! */
  assert(blkCnt != 0);

  /* Set up tweak. */
  ts[0] = ctx->T[0];
  ts[1] = ctx->T[1];

  do
  {
    /* Update processed length. */
    ts[0] += byteCntAdd;

    /* Precompute the key schedule for this block. */
    ks[0] = ctx->X[0];
    ks[1] = ctx->X[1];
    ks[2] = ctx->X[2];
    ks[3] = ctx->X[3];
    ks[4] = ctx->X[4];
    ks[5] = ctx->X[5];
    ks[6] = ctx->X[6];
    ks[7] = ctx->X[7];
    ks[8] = ctx->X[8];
    ks[9] = ctx->X[9];
    ks[10] = ctx->X[10];
    ks[11] = ctx->X[11];
    ks[12] = ctx->X[12];
    ks[13] = ctx->X[13];
    ks[14] = ctx->X[14];
    ks[15] = ctx->X[15];
    ks[16] = ks[0] ^ ks[1] ^ ks[2] ^ ks[3] ^ ks[4] ^ ks[5] ^ ks[6] ^ ks[7] ^ ks[8] ^ ks[9] ^ ks[10] ^ ks[11] ^ ks[12] ^ ks[13] ^ ks[14] ^ ks[15] ^ SKEIN_KS_PARITY;

    ts[2] = ts[0] ^ ts[1];

    /* Get input block in * little-endian format. */
    Skein_Get64_LSB_First(w, blkPtr, WCNT);

    /* Do the first full key injection. */
    X00 = w[0] + ks[0];
    X01 = w[1] + ks[1];
    X02 = w[2] + ks[2];
    X03 = w[3] + ks[3];
    X04 = w[4] + ks[4];
    X05 = w[5] + ks[5];
    X06 = w[6] + ks[6];
    X07 = w[7] + ks[7];
    X08 = w[8] + ks[8];
    X09 = w[9] + ks[9];
    X10 = w[10] + ks[10];
    X11 = w[11] + ks[11];
    X12 = w[12] + ks[12];
    X13 = w[13] + ks[13] + ts[0];
    X14 = w[14] + ks[14] + ts[1];
    X15 = w[15] + ks[15];

#define Round1024(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,pA,pB,pC,pD,pE,pF,ROT,rNum) \
          X##p0 += X##p1; X##p1 = RotL_64(X##p1,ROT##_0); X##p1 ^= X##p0;   \
          X##p2 += X##p3; X##p3 = RotL_64(X##p3,ROT##_1); X##p3 ^= X##p2;   \
          X##p4 += X##p5; X##p5 = RotL_64(X##p5,ROT##_2); X##p5 ^= X##p4;   \
          X##p6 += X##p7; X##p7 = RotL_64(X##p7,ROT##_3); X##p7 ^= X##p6;   \
          X##p8 += X##p9; X##p9 = RotL_64(X##p9,ROT##_4); X##p9 ^= X##p8;   \
          X##pA += X##pB; X##pB = RotL_64(X##pB,ROT##_5); X##pB ^= X##pA;   \
          X##pC += X##pD; X##pD = RotL_64(X##pD,ROT##_6); X##pD ^= X##pC;   \
          X##pE += X##pF; X##pF = RotL_64(X##pF,ROT##_7); X##pF ^= X##pE;   \

#define R1024(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,pA,pB,pC,pD,pE,pF,ROT,rn) \
    Round1024(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,pA,pB,pC,pD,pE,pF,ROT,rn)

/* Inject the key schedule value. */
#define I1024(R)                                                      \
    X00   += ks[r+(R)+ 0];                                            \
    X01   += ks[r+(R)+ 1];                                            \
    X02   += ks[r+(R)+ 2];                                            \
    X03   += ks[r+(R)+ 3];                                            \
    X04   += ks[r+(R)+ 4];                                            \
    X05   += ks[r+(R)+ 5];                                            \
    X06   += ks[r+(R)+ 6];                                            \
    X07   += ks[r+(R)+ 7];                                            \
    X08   += ks[r+(R)+ 8];                                            \
    X09   += ks[r+(R)+ 9];                                            \
    X10   += ks[r+(R)+10];                                            \
    X11   += ks[r+(R)+11];                                            \
    X12   += ks[r+(R)+12];                                            \
    X13   += ks[r+(R)+13] + ts[r+(R)+0];                              \
    X14   += ks[r+(R)+14] + ts[r+(R)+1];                              \
    X15   += ks[r+(R)+15] +    r+(R)   ;                              \
    ks[r  +       (R)+16] = ks[r+(R)-1];  /* rotate key schedule */   \
    ts[r  +       (R)+ 2] = ts[r+(R)-1];

    for (r=1;r <= 2*RCNT;r+=2)    /* loop thru it */
    {
      /* Do 8 full rounds. */
#define R1024_8_rounds(R)                                                         \
        R1024(00,01,02,03,04,05,06,07,08,09,10,11,12,13,14,15,R1024_0,8*(R) + 1); \
        R1024(00,09,02,13,06,11,04,15,10,07,12,03,14,05,08,01,R1024_1,8*(R) + 2); \
        R1024(00,07,02,05,04,03,06,01,12,15,14,13,08,11,10,09,R1024_2,8*(R) + 3); \
        R1024(00,15,02,11,06,13,04,09,14,01,08,05,10,03,12,07,R1024_3,8*(R) + 4); \
        I1024(2*(R));                                                             \
        R1024(00,01,02,03,04,05,06,07,08,09,10,11,12,13,14,15,R1024_4,8*(R) + 5); \
        R1024(00,09,02,13,06,11,04,15,10,07,12,03,14,05,08,01,R1024_5,8*(R) + 6); \
        R1024(00,07,02,05,04,03,06,01,12,15,14,13,08,11,10,09,R1024_6,8*(R) + 7); \
        R1024(00,15,02,11,06,13,04,09,14,01,08,05,10,03,12,07,R1024_7,8*(R) + 8); \
        I1024(2*(R)+1);

      R1024_8_rounds(0);
    }

    /* do the final "feedforward" xor, update context chaining vars */
    ctx->X[0] = X00 ^ w[0];
    ctx->X[1] = X01 ^ w[1];
    ctx->X[2] = X02 ^ w[2];
    ctx->X[3] = X03 ^ w[3];
    ctx->X[4] = X04 ^ w[4];
    ctx->X[5] = X05 ^ w[5];
    ctx->X[6] = X06 ^ w[6];
    ctx->X[7] = X07 ^ w[7];
    ctx->X[8] = X08 ^ w[8];
    ctx->X[9] = X09 ^ w[9];
    ctx->X[10] = X10 ^ w[10];
    ctx->X[11] = X11 ^ w[11];
    ctx->X[12] = X12 ^ w[12];
    ctx->X[13] = X13 ^ w[13];
    ctx->X[14] = X14 ^ w[14];
    ctx->X[15] = X15 ^ w[15];

    ts[1] &= ~SKEIN_T1_FLAG_FIRST;
    blkPtr += SKEIN1024_BLOCK_BYTES;
  } while (--blkCnt);

  ctx->T[0] = ts[0];
  ctx->T[1] = ts[1];
}

/* Init the context for a straight hashing operation. */
void hashsig_skein1024_init(skein1024_ctx_t *ctx, size_t hashBitLen)
{
  /* Config block. */
  uint8_t cfg[SKEIN1024_STATE_BYTES];

  /* Check output hash bit count. */
  assert(hashBitLen > 0);
  ctx->hashBitLen = hashBitLen;

  /* build/process the config block, type == CONFIG (could be precomputed) */

  /* set tweaks: T0=0; T1=CFG | FINAL */
  Skein_Start_New_Type(ctx, CFG_FINAL);

  /* set the schema, version     */
  hashsig_store_le64(cfg, SKEIN_SCHEMA_VER);

  /* hash result length in bits  */
  hashsig_store_le64(cfg + 8, hashBitLen);

  /* Hash configuration. */
  hashsig_store_le64(cfg + 16, SKEIN_CFG_TREE_INFO_SEQUENTIAL);

  /* zero pad config block */
  memset(cfg + 24, 0, sizeof(cfg) - 3 * 8);

  /* zero the chaining variables */
  memset(ctx->X, 0, sizeof(ctx->X));

  /* compute the initial chaining values from config block */
  hashsig_skein1024_process_blocks(ctx, cfg, 1, SKEIN_CFG_STR_LEN);

  /* The chaining vars ctx->X are now initialized for the given hashBitLen. */
  /* Set up to process the data message portion of the hash (default) */

  /* T0=0, T1= MSG type */
  Skein_Start_New_Type(ctx, MSG);
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* process the input bytes */
void hashsig_skein1024_update(skein1024_ctx_t *ctx, const uint8_t *msg, size_t msgByteCnt)
{
  size_t n;

  assert(ctx->bCnt <= SKEIN1024_BLOCK_BYTES); /* catch uninitialized context */

  /* process full blocks, if any */
  if (msgByteCnt + ctx->bCnt > SKEIN1024_BLOCK_BYTES)
  {
    if (ctx->bCnt)            /* finish up any buffered message data */
    {
      n = SKEIN1024_BLOCK_BYTES - ctx->bCnt;  /* # bytes free in buffer b[] */
      if (n)
      {
        assert(n < msgByteCnt); /* check on our logic here */
        memcpy(&ctx->b[ctx->bCnt], msg, n);
        msgByteCnt -= n;
        msg += n;
        ctx->bCnt += n;
      }
      assert(ctx->bCnt == SKEIN1024_BLOCK_BYTES);
      hashsig_skein1024_process_blocks(ctx, ctx->b, 1, SKEIN1024_BLOCK_BYTES);
      ctx->bCnt = 0;
    }
    /* now process any remaining full blocks, directly from input message data */
    if (msgByteCnt > SKEIN1024_BLOCK_BYTES)
    {
      n = (msgByteCnt - 1) / SKEIN1024_BLOCK_BYTES; /* number of full blocks to process */
      hashsig_skein1024_process_blocks(ctx, msg, n, SKEIN1024_BLOCK_BYTES);
      msgByteCnt -= n * SKEIN1024_BLOCK_BYTES;
      msg += n * SKEIN1024_BLOCK_BYTES;
    }
    assert(ctx->bCnt == 0);
  }

  /* copy any remaining source message data bytes into b[] */
  if (msgByteCnt)
  {
    assert(msgByteCnt + ctx->bCnt <= SKEIN1024_BLOCK_BYTES);
    memcpy(&ctx->b[ctx->bCnt], msg, msgByteCnt);
    ctx->bCnt += msgByteCnt;
  }
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* finalize the hash computation and output the result */
void hashsig_skein1024_final(skein1024_ctx_t *ctx, uint8_t *hashVal)
{
  size_t i, n, byteCnt;
  uint64_t X[SKEIN1024_STATE_WORDS];
  assert(ctx->bCnt <= SKEIN1024_BLOCK_BYTES); /* catch uninitialized context */

  ctx->T[1] |= SKEIN_T1_FLAG_FINAL; /* tag as the final block */
  if (ctx->bCnt < SKEIN1024_BLOCK_BYTES)  /* zero pad b[] if necessary */
    memset(&ctx->b[ctx->bCnt], 0, SKEIN1024_BLOCK_BYTES - ctx->bCnt);

  hashsig_skein1024_process_blocks(ctx, ctx->b, 1, ctx->bCnt); /* process the final block */

  /* now output the result */
  byteCnt = (ctx->hashBitLen + 7) >> 3; /* total number of output bytes */

  /* run Threefish in "counter mode" to generate output */
  memset(ctx->b, 0, sizeof(ctx->b));  /* zero out b[], so it can hold the counter */
  memcpy(X, ctx->X, sizeof(X)); /* keep a local copy of counter mode "key" */
  for (i = 0; i * SKEIN1024_BLOCK_BYTES < byteCnt; i++)
  {
    /* build the counter block */
    hashsig_store_le64(ctx->b, i);
    Skein_Start_New_Type(ctx, OUT_FINAL);
    hashsig_skein1024_process_blocks(ctx, ctx->b, 1, sizeof(uint64_t));  /* run "counter mode" */
    n = byteCnt - i * SKEIN1024_BLOCK_BYTES;  /* number of output bytes left to go */
    if (n >= SKEIN1024_BLOCK_BYTES)
      n = SKEIN1024_BLOCK_BYTES;
    Skein_Put64_LSB_First(hashVal + i * SKEIN1024_BLOCK_BYTES, ctx->X, n);  /* "output" the ctr mode bytes */
    memcpy(ctx->X, X, sizeof(X)); /* restore the counter mode key for next time */
  }
}

/**************** Functions to support MAC/tree hashing ***************/
/*   (this code is identical for Optimized and Reference versions)    */

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* finalize the hash computation and output the block, no OUTPUT stage */
void hashsig_skein1024_final_pad(skein1024_ctx_t *ctx, uint8_t *hashVal)
{
  assert(ctx->bCnt <= SKEIN1024_BLOCK_BYTES); /* catch uninitialized context */

  ctx->T[1] |= SKEIN_T1_FLAG_FINAL; /* tag as the final block */
  if (ctx->bCnt < SKEIN1024_BLOCK_BYTES)  /* zero pad b[] if necessary */
    memset(&ctx->b[ctx->bCnt], 0, SKEIN1024_BLOCK_BYTES - ctx->bCnt);
  hashsig_skein1024_process_blocks(ctx, ctx->b, 1, ctx->bCnt); /* process the final block */

  if (hashVal != NULL)
    Skein_Put64_LSB_First(hashVal, ctx->X, SKEIN1024_BLOCK_BYTES);  /* "output" the state bytes */
}

void hashsig_skein1024_prepare_hash (skein1024_ctx_t *ctx, size_t len, const uint8_t *nonce, size_t nonce_len)
{
  static uint8_t personalization[] = "20140717 hashsig@ps-auxw.de libhashsig/hash";
  skein1024_block_t blocks[3];

  /* Zero structures. */
  memset(ctx, 0, sizeof(skein1024_ctx_t));
  memset(blocks, 0, sizeof(blocks));

  /* Set configuration block. */
  blocks[0].type = SKEIN_BLK_TYPE_CFG;

  /* Set up personalization block. */
  blocks[1].type = SKEIN_BLK_TYPE_PERS;
  blocks[1].data = personalization;
  blocks[1].len  = sizeof(personalization);

  /* Set up nonce block. */
  blocks[2].last = 1;
  blocks[2].type = SKEIN_BLK_TYPE_NONCE;
  blocks[2].data = nonce;
  blocks[2].len  = nonce_len;

  /* Process blocks. */
  hashsig_skein1024_full(8 * len, ctx, NULL, blocks);
  Skein_Start_New_Type(ctx, MSG);
}

void hashsig_skein1024_hash (skein1024_ctx_t *prepared, uint8_t *out, const uint8_t *msg, size_t msg_len)
{
  skein1024_ctx_t ctx;

  memcpy(&ctx, prepared, sizeof(ctx));
  hashsig_skein1024_update(&ctx, msg, msg_len);
  hashsig_skein1024_final(&ctx, out);
}

void hashsig_skein1024_sighash (uint8_t *out, size_t len, const uint8_t *pub, size_t pub_len, const uint8_t *msg, size_t msg_len)
{
  static const uint8_t personalization[] = "20140717 hashsig@ps-auxw.de libhashsig/sighash";
  skein1024_block_t blocks[5];
  skein1024_ctx_t ctx;

  /* Zero block structures. */
  memset(blocks, 0, sizeof(blocks));

  /* Set configuration block. */
  blocks[0].type = SKEIN_BLK_TYPE_CFG;

  /* Set up personalization block. */
  blocks[1].type = SKEIN_BLK_TYPE_PERS;
  blocks[1].data = personalization;
  blocks[1].len  = sizeof(personalization);

  /* Set up key block. */
  blocks[2].type = SKEIN_BLK_TYPE_PK;
  blocks[2].data = pub;
  blocks[2].len  = pub_len;

  /* Set up message block. */
  blocks[3].type = SKEIN_BLK_TYPE_MSG;
  blocks[3].data = msg;
  blocks[3].len  = msg_len;

  /* Set up output stage. */
  blocks[4].last = 1;
  blocks[4].type = SKEIN_BLK_TYPE_OUT;

  hashsig_skein1024_full(8 * len, &ctx, out, blocks);
}

/* After this call secret state will be left in the context. Make sure to use the same context for something else after use. */
void hashsig_skein1024_stream (skein1024_ctx_t *ctx, uint8_t *out, size_t len, const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len)
{
  static const uint8_t personalization[] = "20140717 hashsig@ps-auxw.de libhashsig/stream";
  skein1024_block_t blocks[5];

  /* Zero block structures. */
  memset(blocks, 0, sizeof(blocks));

  /* Set up key block. */
  blocks[0].type = SKEIN_BLK_TYPE_KEY;
  blocks[0].data = key;
  blocks[0].len  = key_len;

  /* Set configuration block. */
  blocks[1].type = SKEIN_BLK_TYPE_CFG;

  /* Set up personalization block. */
  blocks[2].type = SKEIN_BLK_TYPE_PERS;
  blocks[2].data = personalization;
  blocks[2].len  = sizeof(personalization);

  /* Set up nonce block. */
  blocks[3].type = SKEIN_BLK_TYPE_NONCE;
  blocks[3].data = nonce;
  blocks[3].len  = nonce_len;

  /* Set up output stage. */
  blocks[4].last = 1;
  blocks[4].type = SKEIN_BLK_TYPE_OUT;

  hashsig_skein1024_full(8 * len, ctx, out, blocks);
}

/* Warning: Do not use, unless you know what you are doing. Processes blocks until last is true. Sets processed to true in each processed block. */
void hashsig_skein1024_full (size_t hash_bits, skein1024_ctx_t *ctx, uint8_t *out, skein1024_block_t blocks[])
{
  uint8_t state[SKEIN1024_STATE_BYTES];
  int found_cfg = 0;
  int last_type = -1;
  size_t i = 0;

  if (!blocks[0].processed)
  {
    memset(ctx, 0, sizeof(skein1024_ctx_t));
    ctx->hashBitLen = hash_bits;
  }
  assert(ctx->hashBitLen == hash_bits && hash_bits > 0);

  do
  {
    /* Ensure that we knowingly have processed a configuration block at some time. */
    if (blocks[i].type == SKEIN_BLK_TYPE_CFG && blocks[i].processed)
      found_cfg = 1;

    /* Ensure that blocks are ordered correctly and have valid types. */
    assert((blocks[i].type == last_type && last_type == SKEIN_BLK_TYPE_MSG) || blocks[i].type > last_type);
    assert((blocks[i].type & SKEIN_BLK_TYPE_MASK) == blocks[i].type);

    /* Do not process blocks twice. */
    if (blocks[i].processed)
    {
      last_type = blocks[i].type;
      continue;
    }
    blocks[i].processed = 1;

    /* Special case for output block. */
    if (blocks[i].type == SKEIN_BLK_TYPE_OUT)
    {
      hashsig_skein1024_final(ctx, out);
      break;
    }

    /* Special case for configuration block. */
    if (blocks[i].type == SKEIN_BLK_TYPE_CFG)
    {
      assert(!found_cfg);

      memset(state, 0, sizeof(state));
      Skein_Start_New_Type(ctx, CFG_FINAL);
      hashsig_store_le64(state, SKEIN_SCHEMA_VER);
      hashsig_store_le64(state + 8, hash_bits);
      hashsig_store_le64(state + 16, SKEIN_CFG_TREE_INFO_SEQUENTIAL);
      hashsig_skein1024_process_blocks(ctx, state, 1, SKEIN_CFG_STR_LEN);
      found_cfg = 1;
      last_type = blocks[i].type;
      ctx->bCnt = 0;
      if (blocks[i].last)
        break;
      else
        continue;
    }

    /* First, finalize last block and initialize new one, if necessary. */
    if (blocks[i].type != last_type)
    {
      Skein_Set_T0_T1(ctx, 0, SKEIN_T1_FLAG_FIRST | ((uint64_t)blocks[i].type << SKEIN_T1_POS_BLK_TYPE));
      ctx->bCnt = 0;
    }

    /* Process regular block data. */
    hashsig_skein1024_update(ctx, blocks[i].data, blocks[i].len);

    /* Finish up, unless it is a message block, which might be continued. */
    if (blocks[i].type != SKEIN_BLK_TYPE_MSG)
    {
      hashsig_skein1024_final_pad(ctx, NULL);
    }

    /* Finish up and go to next block. */
    last_type = blocks[i].type;
  } while (!blocks[i++].last);

  assert(found_cfg);
}
