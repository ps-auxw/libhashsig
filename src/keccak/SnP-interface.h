/*
Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
denoted as "the implementer".

For more information, feedback or questions, please refer to our websites:
http://keccak.noekeon.org/
http://keyak.noekeon.org/
http://ketje.noekeon.org/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef SNPINTERFACE_H
#define SNPINTERFACE_H

#include "KeccakF-1600-interface.h"

#define SnP_width                           KeccakF_width
#define SnP_stateSizeInBytes                KeccakF_stateSizeInBytes
#define SnP_laneLengthInBytes               KeccakF_laneInBytes

#define SnP_StaticInitialize                hashsig_KeccakF1600_Initialize
#define SnP_Initialize                      hashsig_KeccakF1600_StateInitialize
#define SnP_XORBytesInLane                  hashsig_KeccakF1600_StateXORBytesInLane
#define SnP_XORLanes                        hashsig_KeccakF1600_StateXORLanes
#define SnP_OverwriteBytesInLane            hashsig_KeccakF1600_StateOverwriteBytesInLane
#define SnP_OverwriteLanes                  hashsig_KeccakF1600_StateOverwriteLanes
#define SnP_OverwriteWithZeroes             hashsig_KeccakF1600_StateOverwriteWithZeroes
#define SnP_ComplementBit                   hashsig_KeccakF1600_StateComplementBit
#define SnP_Permute                         hashsig_KeccakF1600_StatePermute
#define SnP_ExtractBytesInLane              hashsig_KeccakF1600_StateExtractBytesInLane
#define SnP_ExtractLanes                    hashsig_KeccakF1600_StateExtractLanes
#define SnP_ExtractAndXORBytesInLane        hashsig_KeccakF1600_StateExtractAndXORBytesInLane
#define SnP_ExtractAndXORLanes              hashsig_KeccakF1600_StateExtractAndXORLanes

#include "SnP-Relaned.h"

#define SnP_FBWL_Absorb                     hashsig_KeccakF1600_FBWL_Absorb
#define SnP_FBWL_Squeeze                    hashsig_KeccakF1600_FBWL_Squeeze
#define SnP_FBWL_Wrap                       hashsig_KeccakF1600_FBWL_Wrap
#define SnP_FBWL_Unwrap                     hashsig_KeccakF1600_FBWL_Unwrap

size_t hashsig_KeccakF1600_FBWL_Absorb(void *state, unsigned int laneCount, const unsigned char *data, const size_t dataByteLen, unsigned char trailingBits);
size_t hashsig_KeccakF1600_FBWL_Squeeze(void *state, unsigned int laneCount, unsigned char *data, size_t dataByteLen);
void hashsig_KeccakF1600_StateXORLanes(void *state, const unsigned char *data, unsigned int laneCount);
void hashsig_KeccakF1600_StateXORBytesInLane(void *state, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length);
void hashsig_KeccakF1600_StateExtractLanes(const void *state, unsigned char *data, unsigned int laneCount);
void hashsig_KeccakF1600_StateExtractBytesInLane(const void *state, unsigned int lanePosition, unsigned char *data, unsigned int offset, unsigned int length);

#endif /* SNPINTERFACE_H */
