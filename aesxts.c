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

#include "aesxts.h"
#include <sys/types.h>
#include <string.h>

INT_RETURN xts_key(const unsigned char key[], int key_len, xts_ctx ctx[1])
{
	int aes_klen_by;

	switch(key_len)
	{
	default:    return EXIT_FAILURE;
	case 32:
	case 256:   aes_klen_by = 16; break;
	case 64:
	case 512:   aes_klen_by = 32; break;
	}

	return aes_encrypt_key(key, aes_klen_by, ctx->enc_ctx) == EXIT_SUCCESS &&
		   aes_decrypt_key(key, aes_klen_by, ctx->dec_ctx) == EXIT_SUCCESS &&
		   aes_encrypt_key(key + aes_klen_by, aes_klen_by, ctx->twk_ctx) == EXIT_SUCCESS
		? EXIT_SUCCESS : EXIT_FAILURE;
}

static void xts_mult_x(uint8_t *I)
{
	uint32_t x;
	uint8_t t, tt;

	for(x = t = 0; x < 16; x++) 
	{
		tt   = I[x] >> 7;
		I[x] = ((I[x] << 1) | t) & 0xFF;
		t    = tt;
	}
	if(tt) 
	{
		I[0] ^= 0x87;
	} 
}

static int tweak_crypt(const uint8_t *P, uint8_t *C, uint8_t *T, const aes_encrypt_ctx *ctx)
{
	uint32_t x, err;

	for(x = 0; x < 16; x += sizeof(uint64_t)) 
		*((uint64_t*)&C[x]) = *((uint64_t*)&P[x]) ^ *((uint64_t*)&T[x]);
     
	err = aes_encrypt(C, C, ctx);

	for(x = 0; x < 16; x += sizeof(uint64_t)) 
		*((uint64_t*)&C[x]) ^= *((uint64_t*)&T[x]);

	xts_mult_x(T);

	return EXIT_SUCCESS;
}   

INT_RETURN xts_encrypt_sector(unsigned char sector[], unsigned char sector_address[],
							  unsigned int sector_len, const xts_ctx ctx[1])
{
	uint8_t PP[16], CC[16], T[16];
	uint32_t i, m, mo, err;
	unsigned char *pt = sector;
	unsigned char *ct = (unsigned char*)malloc(sector_len), *cc = ct;

	m  = sector_len >> 4;
	mo = sector_len & 15;

	if(m == 0) 
		return EXIT_FAILURE;

	memcpy(T, sector_address, 16);
	if((err = aes_encrypt(T, T, ctx->twk_ctx)) != EXIT_SUCCESS)
		return err;

	/* for i = 0 to m-2 do */
	for(i = 0; i < (mo == 0 ? m : m - 1); i++)
	{
		err = tweak_crypt(pt, ct, T, ctx->enc_ctx);
		ct += 16;
		pt += 16;
	}
   
	/* if sector_len not divide 16 then */
	if(mo > 0) 
	{
		if((err = tweak_crypt(pt, CC, T, ctx->enc_ctx)) != EXIT_SUCCESS)
			return err;

		/* Cm = first sector_len % 16 bytes of CC */
		for(i = 0; i < mo; i++) 
		{
			PP[i] = pt[16+i];
			ct[16+i] = CC[i];
		}

		for(; i < 16; i++) 
		{
			PP[i] = CC[i];
		}

		/* Cm-1 = Tweak encrypt PP */
		if((err = tweak_crypt(PP, ct, T, ctx->enc_ctx)) != EXIT_SUCCESS)
			return err;
	}
	memcpy(pt, ct, sector_len);
	free(cc);
	return EXIT_SUCCESS;
}

static int tweak_uncrypt(const uint8_t *C, uint8_t *P, uint8_t *T, const aes_decrypt_ctx *ctx)
{
	uint32_t x, err;

	for(x = 0; x < 16; x += sizeof(uint64_t)) 
		*((uint64_t*)&P[x]) = *((uint64_t*)&C[x]) ^ *((uint64_t*)&T[x]);
     
	err = aes_decrypt(P, P, ctx);  

	for(x = 0; x < 16; x += sizeof(uint64_t)) 
		*((uint64_t*)&P[x]) ^=  *((uint64_t*)&T[x]);

	xts_mult_x(T);

	return err;
}   

INT_RETURN xts_decrypt_sector(unsigned char sector[], unsigned char sector_address[],
							  unsigned int sector_len, const xts_ctx ctx[1])
{
	uint8_t PP[16], CC[16], T[16];
	uint32_t i, m, mo, err;
	unsigned char *ct = sector;
	unsigned char *pt = (unsigned char*)malloc(sector_len), *pp = pt;

	/* get number of blocks */
	m  = sector_len >> 4;
	mo = sector_len & 15;

	/* must have at least one full block */
	if(m == 0) 
		return EXIT_FAILURE;

	/* encrypt the tweak , yes - encrypt */
	memcpy(T, sector_address, 16);
	if((err = aes_encrypt(T, T, ctx->twk_ctx)) != EXIT_SUCCESS)
		return err;

	/* for i = 0 to m-2 do */
	for(i = 0; i < (mo == 0 ? m : m - 1); i++)
	{
		err = tweak_uncrypt(ct, pt, T, ctx->dec_ctx);
		ct += 16;
		pt += 16;
	}
   
	/* if sector_len not divide 16 then */
	if(mo > 0) 
	{
		memcpy(CC, T, 16);
		xts_mult_x(CC);

		/* PP = tweak decrypt block m-1 */
		if((err = tweak_uncrypt(ct, PP, CC, ctx->dec_ctx)) != EXIT_SUCCESS)
			return err;

		/* Pm = first sector_len % 16 bytes of PP */
		for(i = 0; i < mo; i++) 
		{
			CC[i]    = ct[16+i];
			pt[16+i] = PP[i];
		}

		for(; i < 16; i++) 
		{
			CC[i] = PP[i];
		}

		/* Pm-1 = Tweak uncrypt CC */
		if((err = tweak_uncrypt(CC, pt, T, ctx->dec_ctx)) != EXIT_SUCCESS)
			return err;
	}

	memcpy(ct, pt, sector_len);
	free(pp);
	return EXIT_SUCCESS;
}
