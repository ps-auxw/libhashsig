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

#ifndef LMFS_DEFS_H
#define LMFS_DEFS_H

#include <stdint.h>
#include "hashsig_defs.h"
#include "hashsig.h"

#define LMFS_TREE_HEIGHT 8 /* 8 or 16 */
#define LMFS_TREE_BITS 256

#define LMFS_TREES (LMFS_TREE_BITS / LMFS_TREE_HEIGHT)
#define LMFS_HASH_BYTES (((LMFS_TREE_BITS / 8) > LDWM_N) ? (LMFS_TREE_BITS / 8) : LDWM_N)
#define LMFS_DEPTH_BYTES ((LMFS_TREE_HEIGHT == 8) ? 1 : 2)
#define LMFS_LEAVES (1 << LMFS_TREE_HEIGHT)
#define LMFS_PATH_LEN (LMFS_TREE_HEIGHT * LDWM_N)
#define LMFS_SIG_HEADER 1
#define LMFS_SIG_LEN (LMFS_TREES * LMFS_PATH_LEN + LMFS_TREES * LDWM_N + LMFS_TREES * LDWM_SIG_LEN + LMFS_SIG_HEADER)

void hashsig_lmfs_tree (hashsig_t *ctx, const uint8_t *hash, const uint8_t depth, uint8_t *root_pub, uint8_t *mt_path, uint8_t *priv, uint8_t *pub);
void hashsig_lmfs_sign (hashsig_t *ctx, uint8_t *sig, const uint8_t *message, const size_t len);
int hashsig_lmfs_verify (hashsig_t *ctx, const uint8_t *pub, const uint8_t *sig, const uint8_t *message, const size_t len);
void hashsig_lmfs_public_key (hashsig_t *ctx, uint8_t *pub);

#endif /* LMFS_DEFS_H */
