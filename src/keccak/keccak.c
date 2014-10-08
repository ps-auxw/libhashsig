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
#include <string.h>
#include "KeccakHash.h"
#include "keccak.h"

void hashsig_keccak_hash (keccak_ctx_t *ctx, uint8_t *out, const uint8_t *in, const size_t len)
{
	keccak_ctx_t hi;

	assert(ctx != NULL);
	memcpy(&hi, ctx, sizeof(hi));

	hashsig_Keccak_HashUpdate(&hi, in, len * 8);
	hashsig_Keccak_HashFinal(&hi, out);
}

void hashsig_keccak_prepare_hash (keccak_ctx_t *ctx, const size_t len, const uint8_t *nonce, const size_t nonce_len)
{
	uint8_t s_len = nonce_len;

	assert(ctx != NULL);
	hashsig_Keccak_HashInitialize(ctx, 576,  1024, len * 8, 0x06);

	/* Prefix with depth and position in tree to personalize. */
	hashsig_Keccak_HashUpdate(ctx, &s_len, 1);
	if (nonce_len)
		hashsig_Keccak_HashUpdate(ctx, nonce, nonce_len * 8);
}

void hashsig_keccak_sighash (uint8_t *out, size_t len, const uint8_t *pub, size_t pub_len, const uint8_t *msg, size_t msg_len)
{
	uint8_t sig_pub_separator[8] = { 'H', 'A', 'S', 'H', 'S', 'I', 'G', 'S' };
	keccak_ctx_t hi;

	assert(pub != NULL);
	assert(msg != NULL);

	hashsig_Keccak_HashInitialize(&hi, 576,  1024, len * 8, 0x06);

	/* Add the public key to the message for personalization purposes. */
	hashsig_Keccak_HashUpdate(&hi, sig_pub_separator, sizeof(sig_pub_separator) * 8);
	hashsig_Keccak_HashUpdate(&hi, (uint8_t *)&pub_len, sizeof(pub_len));
	hashsig_Keccak_HashUpdate(&hi, pub, pub_len * 8);
	hashsig_Keccak_HashUpdate(&hi, sig_pub_separator, sizeof(sig_pub_separator) * 8);

	hashsig_Keccak_HashUpdate(&hi, msg, msg_len * 8);
	hashsig_Keccak_HashFinal(&hi, out);
}

void hashsig_keccak_stream (keccak_ctx_t *ctx, uint8_t *out, size_t len, const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len)
{
	uint8_t key_separator[8] = { 'H', 'A', 'S', 'H', 'S', 'I', 'G', 'K' };
	uint8_t nonce_separator[8] = { 'H', 'A', 'S', 'H', 'S', 'I', 'G', 'N' };

	assert(ctx != NULL);
	assert(key != NULL);
	assert(nonce != NULL);

	hashsig_Keccak_HashInitialize(ctx, 576,  1024, len * 8, 0x06);

	/* Add secret key. */
	hashsig_Keccak_HashUpdate(ctx, key_separator, sizeof(key_separator) * 8);
	hashsig_Keccak_HashUpdate(ctx, (uint8_t *)&key_len, sizeof(key_len));
	hashsig_Keccak_HashUpdate(ctx, key, key_len * 8);
	hashsig_Keccak_HashUpdate(ctx, key_separator, sizeof(key_separator) * 8);

	/* Add position in tree. */
	hashsig_Keccak_HashUpdate(ctx, nonce_separator, sizeof(nonce_separator) * 8);
	hashsig_Keccak_HashUpdate(ctx, (uint8_t *)&nonce_len, sizeof(nonce_len));
	hashsig_Keccak_HashUpdate(ctx, nonce, nonce_len * 8);
	hashsig_Keccak_HashUpdate(ctx, nonce_separator, sizeof(nonce_separator) * 8);

	/* Squeeze necessary amount of bits from the sponge. */
	hashsig_Keccak_HashFinal(ctx, out);
}
