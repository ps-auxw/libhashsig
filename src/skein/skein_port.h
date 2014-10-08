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

#ifndef SKEIN_PORT_H
#define SKEIN_PORT_H
/*******************************************************************
**
** Platform-specific definitions for Skein hash function.
**
** Source code author: Doug Whiting, 2008.
**
** This algorithm and source code is released to the public domain.
**
** Many thanks to Brian Gladman for his portable header files.
**
** To port Skein to an "unsupported" platform, change the definitions
** in this file appropriately.
** 
********************************************************************/

#include <stdint.h>

#ifndef RotL_64
#define RotL_64(x,N)    (((x) << (N)) | ((x) >> (64-(N))))
#endif

/*
 * Skein is "natively" little-endian (unlike SHA-xxx), for optimal
 * performance on x86 CPUs.  The Skein code requires the following
 * definitions for dealing with endianness:
 *
 *    Skein_Put64_LSB_First
 *    Skein_Get64_LSB_First
 *
 * An "auto-detect" of endianness is attempted below. If the default handling
 * doesn't work well, the user may insert platform-specific code instead (e.g.,
 * for big-endian CPUs).
 *
 */

#include "brg_endian.h"                     /* get endianness selection */
#if   PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN
    /* here for big-endian CPUs */
#elif PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN
    /* here for x86 and x86-64 CPUs (and other detected little-endian CPUs) */
#if   PLATFORM_MUST_ALIGN == 0              /* ok to use "fast" versions? */
#define Skein_Put64_LSB_First(dst08,src64,bCnt) memcpy(dst08,src64,bCnt)
#define Skein_Get64_LSB_First(dst64,src08,wCnt) memcpy(dst64,src08,8*(wCnt))
#endif
#else
#error "Skein needs endianness setting!"
#endif

/*
 ******************************************************************
 *      Provide any definitions still needed.
 ******************************************************************
 */
#ifndef Skein_Put64_LSB_First
static void    Skein_Put64_LSB_First(uint8_t *dst,const uint64_t *src,size_t bCnt)
    { /* this version is fully portable (big-endian or little-endian), but slow */
    size_t n;

    for (n=0;n<bCnt;n++)
        dst[n] = (uint8_t) (src[n>>3] >> (8*(n&7)));
    }
#endif   /* ifndef Skein_Put64_LSB_First */


#ifndef Skein_Get64_LSB_First
static void    Skein_Get64_LSB_First(uint64_t *dst,const uint8_t *src,size_t wCnt)
    { /* this version is fully portable (big-endian or little-endian), but slow */
    size_t n;

    for (n=0;n<8*wCnt;n+=8)
        dst[n/8] = (((uint64_t) src[n  ])      ) +
                   (((uint64_t) src[n+1]) <<  8) +
                   (((uint64_t) src[n+2]) << 16) +
                   (((uint64_t) src[n+3]) << 24) +
                   (((uint64_t) src[n+4]) << 32) +
                   (((uint64_t) src[n+5]) << 40) +
                   (((uint64_t) src[n+6]) << 48) +
                   (((uint64_t) src[n+7]) << 56) ;
    }
#endif   /* ifndef Skein_Get64_LSB_First */

#endif /* SKEIN_PORT_H */
