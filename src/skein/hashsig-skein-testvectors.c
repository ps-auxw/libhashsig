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

#include <stdio.h>
#include <string.h>

#include "hashsig.h"
#include "skein.h"


/* Test program */

void dump_hex (const uint8_t *buf, const size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
    printf("%02x", buf[i]);
  printf("\n");
}

int main (int argc, char *argv[])
{
	uint8_t hash[1024/8] = { 0 };
	uint8_t msg[1] = { 0xff };
	uint8_t msg2[0x80];
	uint8_t msg3[0x100];
  skein1024_block_t blocks[3];
  skein1024_ctx_t sctx;
  skein1024_ctx_t *ctx = &sctx;
	int i;

  /* Zero structures. */
  memset(blocks, 0, sizeof(blocks));
  memset(ctx, 0, sizeof(*ctx));

  /* Set configuration block. */
  blocks[0].type = SKEIN_BLK_TYPE_CFG;

  /* Set up message block. */
  blocks[1].type = SKEIN_BLK_TYPE_MSG;
  blocks[1].data = msg;
  blocks[1].len  = sizeof(msg);

  /* Set up output stage. */
  blocks[2].last = 1;
  blocks[2].type = SKEIN_BLK_TYPE_OUT;

	/* Output result of first test vector. */
  hashsig_skein1024_full(sizeof(hash) * 8, ctx, hash, blocks);
	dump_hex(hash, sizeof(hash));


  /* Zero structures. */
  memset(blocks, 0, sizeof(blocks));
  memset(ctx, 0, sizeof(*ctx));

  /* Set configuration block. */
  blocks[0].type = SKEIN_BLK_TYPE_CFG;

  /* Set up message block. */
	for (i = 0xff; i >= 0x80; i--)
		msg2[0xff - i] = i;
  blocks[1].type = SKEIN_BLK_TYPE_MSG;
  blocks[1].data = msg2;
  blocks[1].len  = sizeof(msg2);

  /* Set up output stage. */
  blocks[2].last = 1;
  blocks[2].type = SKEIN_BLK_TYPE_OUT;

	/* Output result of first test vector. */
  hashsig_skein1024_full(sizeof(hash) * 8, ctx, hash, blocks);
	dump_hex(hash, sizeof(hash));


  /* Zero structures. */
  memset(blocks, 0, sizeof(blocks));
  memset(ctx, 0, sizeof(*ctx));

  /* Set configuration block. */
  blocks[0].type = SKEIN_BLK_TYPE_CFG;

  /* Set up message block. */
	for (i = 0xff; i >= 0x00; i--)
		msg3[0xff - i] = i;
  blocks[1].type = SKEIN_BLK_TYPE_MSG;
  blocks[1].data = msg3;
  blocks[1].len  = sizeof(msg3);

  /* Set up output stage. */
  blocks[2].last = 1;
  blocks[2].type = SKEIN_BLK_TYPE_OUT;

	/* Output result of first test vector. */
  hashsig_skein1024_full(sizeof(hash) * 8, ctx, hash, blocks);
	dump_hex(hash, sizeof(hash));
}
