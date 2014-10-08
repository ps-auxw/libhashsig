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

/* Lazy Merkle Forest Signatures */

#include <string.h>

#include "ldwm_defs.h"
#include "lmfs_defs.h"
#include "keccak.h"
#include "util.h"

void hashsig_lmfs_tree (hashsig_t *ctx, const uint8_t *hash, const uint8_t depth, uint8_t *root_pub, uint8_t *mt_path, uint8_t *priv, uint8_t *pub)
{
  uint8_t *priv_leaves = ctx->priv_scratch;
  uint8_t *pub_leaves = ctx->pub_scratch;
  uint16_t leaf;
  size_t i, j;

  /* Generate leaves and select target leaf from message hash. */
  if (LMFS_TREE_HEIGHT == 16)
    leaf = hashsig_load_le16(hash + depth * 2);
  else
    leaf = hash[depth];

  /* After this call secret state will be left in the context. The subsequent hashsig_keccak_prepare_hash call overwrites it. */
  hashsig_keccak_stream(ctx->keccak_ctx, priv_leaves, LMFS_LEAVES * LDWM_SIG_LEN, ctx->priv, ctx->priv_len, hash, depth * LMFS_DEPTH_BYTES);

  /* Personalize hash function for current depth. Also overwrites secret state. */
  hashsig_keccak_prepare_hash(ctx->keccak_ctx, LDWM_N, hash, depth);

  /* Store hash selected leaf private key. */
  if (priv != NULL)
    memcpy(priv, priv_leaves + leaf * LDWM_SIG_LEN, LDWM_SIG_LEN);

  /* Generate public keys from private keys. */
  for (i = 0; i < LMFS_LEAVES; i++)
    hashsig_ldwm_public_key(ctx, priv_leaves + i * LDWM_SIG_LEN, pub_leaves + i * LDWM_N);

  /* Store hash selected leaf public key. */
  if (pub != NULL)
    memcpy(pub, pub_leaves + leaf * LDWM_N, LDWM_N);

  /* Build Merkle tree path and root node. */
  for (i = LMFS_LEAVES; i > 1; i >>= 1)
    for (j = 0; j < i; j += 2)
    {
      /* Check if we need to build a path through the Merkle tree. */
      if (mt_path != NULL)
      {
        /* If this hash contains the target leaf or a parent, store its sibling in the Merkle tree path. */
        if (j == leaf)
        {
          /* We are hashing the current leaf with the value to its right. Store that value. */
          memcpy(mt_path, pub_leaves + (j + 1) * LDWM_N, LDWM_N);
          mt_path += LDWM_N;
          leaf = j >> 1;
        }
        else if (j + 1 == leaf)
        {
          /* We are hashing the current leaf with the value to its left. Store that value. */
          memcpy(mt_path, pub_leaves + j * LDWM_N, LDWM_N);
          mt_path += LDWM_N;
          leaf = j >> 1;
        }
      }
      /* Hash sibling nodes. */
      LDWM_H(pub_leaves + (j >> 1) * LDWM_N, pub_leaves + j * LDWM_N, LDWM_N * 2);
    }

  /* Store root of the Merkle tree. */
  memcpy(root_pub, pub_leaves, LDWM_N);
}

/* Returned value has to be freed using hashsig_free. */
void hashsig_lmfs_sign (hashsig_t *ctx, uint8_t *sig, const uint8_t *message, const size_t len)
{
  uint8_t *buf = sig;
  uint8_t hash[LMFS_HASH_BYTES];
  uint8_t root[LDWM_N];
  uint8_t last[LDWM_N];
  int i;

  /* Set signature header. */
  memcpy(buf, &ctx->type, LMFS_SIG_HEADER);
  buf += LMFS_SIG_HEADER;

  /* Hash message and set it up as the first value to be signed. */
  hashsig_keccak_sighash(hash, LMFS_HASH_BYTES, ctx->pub, LDWM_N, message, len);
  memcpy(last, hash, LDWM_N);

  /* Start at the deepest level. */
  for (i = LMFS_TREES - 1; i >= 0; i--)
  {
    /* Generate leaves etc. */
    hashsig_lmfs_tree(ctx, hash, i, root, buf + LDWM_N + LDWM_SIG_LEN, buf + LDWM_N, buf);

    /* Sign message or root of lower tree. */
    hashsig_ldwm_sign(ctx, buf + LDWM_N, last, LDWM_N, 1);

    /* Store current root as the next value to be signed. */
    memcpy(last, root, LDWM_N);

    /* Shift target buffer for the next part of the signature. */
    buf += LDWM_N + LDWM_SIG_LEN + LMFS_PATH_LEN;
  }
}

int hashsig_lmfs_verify (hashsig_t *ctx, const uint8_t *pub, const uint8_t *sig, const uint8_t *message, const size_t len)
{
  uint8_t hash[LMFS_HASH_BYTES];
  uint8_t last[LDWM_N];
  uint8_t mt_buf[LDWM_N * 3];
  uint16_t leaf;
  int i, j;

  /* Check signature header. */
  if (memcmp(sig, &ctx->type, LMFS_SIG_HEADER))
      return -1;
  sig += LMFS_SIG_HEADER;

  /* Hash message and set it up as the first value to be verified. */
  hashsig_keccak_sighash(hash, LMFS_HASH_BYTES, pub, LDWM_N, message, len);
  memcpy(last, hash, LDWM_N);

  /* Start at the deepest level. */
  for (i = LMFS_TREES - 1; i >= 0; i--)
  {
    /* Personalize hash function for current depth. */
    hashsig_keccak_prepare_hash(ctx->keccak_ctx, LDWM_N, hash, i);

    /* Verify LDWM signature on last public key or message hash. */
    if (hashsig_ldwm_verify(ctx, sig, sig + LDWM_N, last, LDWM_N, 1))
      return 1;

    /* Apply Merkle tree path to hash to transform it to tree's root node. First, determine the current leaf's position. */
    if (LMFS_TREE_HEIGHT == 16)
      leaf = hashsig_load_le16(hash + i * 2);
    else
      leaf = hash[i];

    /* Copy the current hash into the middle of a three hash wide buffer. */
    memcpy(mt_buf + LDWM_N, sig, LDWM_N);

    /* Advance signature buffer beyond public key and signature. */
    sig += LDWM_N + LDWM_SIG_LEN;

    /* Follow Merkle tree path, starting on the bottom level. */
    for (j = LMFS_LEAVES; j > 1; j >>= 1)
    {
      /* Check if position of current leaf is odd or even. */
      if (leaf & 1)
      {
        /* Leaf is odd. Copy next path element to the left and hash. */
        memcpy(mt_buf, sig, LDWM_N);
        LDWM_H(mt_buf + LDWM_N, mt_buf, 2 * LDWM_N);
      }
      else
      {
        /* Leaf is even. Copy next path element to the right and hash. */
        memcpy(mt_buf + 2 * LDWM_N, sig, LDWM_N);
        LDWM_H(mt_buf + LDWM_N, mt_buf + LDWM_N, 2 * LDWM_N);
      }

      /* Go up to next level and advance signature buffer over the current path element. */
      leaf >>= 1;
      sig += LDWM_N;
    }

    /* Make this tree's root node the next hash to check the signature of. */
    memcpy(last, mt_buf + LDWM_N, LDWM_N);
  }

  /* If it can be proven that the last public key is part of the Merkle tree, for which the public key is the root node, the signature is valid. */
  if (memcmp(last, pub, LDWM_N))
    return 1;

  /* Otherwise it is invalid. */
  return 0;
}

void hashsig_lmfs_public_key (hashsig_t *ctx, uint8_t *pub)
{
  uint8_t hash[LMFS_HASH_BYTES] = { 0 };

  /* Personalize hash function for current depth. */
  hashsig_keccak_prepare_hash(ctx->keccak_ctx, LDWM_N, NULL, 0);

  /* Calculate root node for top-most Merkle tree to use as public key. */
  hashsig_lmfs_tree(ctx, hash, 0, pub, NULL, NULL, NULL);
}
