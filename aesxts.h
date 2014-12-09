/*
 * Copyright (c) 2010 Apple Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 *  aesxts.h
 *
 *
 */

#include "stdint.h"
#include "aes.h"

#ifndef _AESXTS_H
#define _AESXTS_H

#if defined(__cplusplus)
extern "C"
{
#endif

/*
 * The context for XTS-AES
 */

#if 1
#  define LONG_LBA
#endif

typedef struct {
	aes_encrypt_ctx twk_ctx[1];
	aes_encrypt_ctx enc_ctx[1];
	aes_decrypt_ctx dec_ctx[1];
} xts_ctx;

#if defined( LONG_LBA )
typedef uint64_t lba_type;
#else
typedef uint32_t lba_type;
#endif

INT_RETURN xts_key(const unsigned char key[], int key_len, xts_ctx ctx[1]);

INT_RETURN xts_encrypt_sector(unsigned char sector[], unsigned char sector_address[],
	unsigned int sector_len, const xts_ctx ctx[1] );

INT_RETURN xts_decrypt_sector(unsigned char sector[], unsigned char sector_address[],
	unsigned int sector_len, const xts_ctx ctx[1]);

#if defined(__cplusplus)
}
#endif

#endif /* _AESXTS_H */