/*
 ---------------------------------------------------------------------------
 Copyright (c) 1998-2008, Brian Gladman, Worcester, UK. All rights reserved.

 LICENSE TERMS

 The redistribution and use of this software (with or without changes)
 is allowed without the payment of fees or royalties provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 20/12/2007

 My thanks to both Doug Whiting and Olaf Pors for their much appreciated
 assistance in debugging and testing this code.
*/

#include "mode_hdr.h"
#include "xts.h"

UNIT_TYPEDEF(buf_unit, UNIT_BITS);
BUFR_TYPEDEF(buf_type, UNIT_BITS, AES_BLOCK_SIZE);

void gf_mulx(void *x)
{
#if UNIT_BITS == 8

    uint8_t i = 16, t = ((uint8_t*)x)[15];
    while(--i)
        ((uint8_t*)x)[i] = (((uint8_t*)x)[i] << 1) | (((uint8_t*)x)[i - 1] & 0x80 ? 1 : 0);
    ((uint8_t*)x)[0] = (((uint8_t*)x)[0] << 1) ^ (t & 0x80 ? 0x87 : 0x00);

#elif PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN

#  if UNIT_BITS == 64

#   define GF_MASK  li_64(8000000000000000) 
#   define GF_XOR   li_64(0000000000000087) 
    uint64_t _tt = ((UPTR_CAST(x,64)[1] & GF_MASK) ? GF_XOR : 0);
    UPTR_CAST(x,64)[1] = (UPTR_CAST(x,64)[1] << 1) | (UPTR_CAST(x,64)[0] & GF_MASK ? 1 : 0);
    UPTR_CAST(x,64)[0] = (UPTR_CAST(x,64)[0] << 1) ^ _tt;

#  else /* UNIT_BITS == 32 */

#   define GF_MASK  li_32(80000000) 
#   define GF_XOR   li_32(00000087) 
    uint32_t _tt = ((UPTR_CAST(x,32)[3] & GF_MASK) ? GF_XOR : 0);;
    UPTR_CAST(x,32)[3] = (UPTR_CAST(x,32)[3] << 1) | (UPTR_CAST(x,32)[2] & GF_MASK ? 1 : 0);
    UPTR_CAST(x,32)[2] = (UPTR_CAST(x,32)[2] << 1) | (UPTR_CAST(x,32)[1] & GF_MASK ? 1 : 0);
    UPTR_CAST(x,32)[1] = (UPTR_CAST(x,32)[1] << 1) | (UPTR_CAST(x,32)[0] & GF_MASK ? 1 : 0);
    UPTR_CAST(x,32)[0] = (UPTR_CAST(x,32)[0] << 1) ^ _tt;

#  endif

#else /* PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN */

#  if UNIT_BITS == 64

#   define MASK_01  li_64(0101010101010101)
#   define GF_MASK  li_64(0000000000000080) 
#   define GF_XOR   li_64(8700000000000000) 
    uint64_t _tt = ((UPTR_CAST(x,64)[1] & GF_MASK) ? GF_XOR : 0);
    UPTR_CAST(x,64)[1] =  ((UPTR_CAST(x,64)[1] << 1) & ~MASK_01) 
        | (((UPTR_CAST(x,64)[1] >> 15) | (UPTR_CAST(x,64)[0] << 49)) & MASK_01);
    UPTR_CAST(x,64)[0] = (((UPTR_CAST(x,64)[0] << 1) & ~MASK_01) 
        |  ((UPTR_CAST(x,64)[0] >> 15) & MASK_01)) ^ _tt;

#  else /* UNIT_BITS == 32 */

#   define MASK_01  li_32(01010101)
#   define GF_MASK  li_32(00000080) 
#   define GF_XOR   li_32(87000000) 
    uint32_t _tt = ((UPTR_CAST(x,32)[3] & GF_MASK) ? GF_XOR : 0);
    UPTR_CAST(x,32)[3] =  ((UPTR_CAST(x,32)[3] << 1) & ~MASK_01) 
        | (((UPTR_CAST(x,32)[3] >> 15) | (UPTR_CAST(x,32)[2] << 17)) & MASK_01);
    UPTR_CAST(x,32)[2] =  ((UPTR_CAST(x,32)[2] << 1) & ~MASK_01) 
        | (((UPTR_CAST(x,32)[2] >> 15) | (UPTR_CAST(x,32)[1] << 17)) & MASK_01);
    UPTR_CAST(x,32)[1] =  ((UPTR_CAST(x,32)[1] << 1) & ~MASK_01) 
        | (((UPTR_CAST(x,32)[1] >> 15) |   (UPTR_CAST(x,32)[0] << 17)) & MASK_01);
    UPTR_CAST(x,32)[0] = (((UPTR_CAST(x,32)[0] << 1) & ~MASK_01) 
        |  ((UPTR_CAST(x,32)[0] >> 15) & MASK_01)) ^ _tt;

#  endif

#endif
}

INT_RETURN xts_key( const unsigned char key[], int key_len, xts_ctx ctx[1] )
{   int aes_klen_by;

    switch( key_len )
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

INT_RETURN xts_encrypt( unsigned char sector[], unsigned int sector_len_bits,
						unsigned char sector_address[], const xts_ctx ctx[1] )
{   
    buf_type twk;
	uint8_t bits = sector_len_bits & 7;
	uint8_t *pos = sector, *hi = pos + ((sector_len_bits + 7) >> 3),
	        *hi_byte = pos + (sector_len_bits >> 3);

    xor_function f_ptr = (!ALIGN_OFFSET(sector, UNIT_BITS >> 3) ? xor_block_aligned : xor_block );

    if( sector_len_bits < 8 * AES_BLOCK_SIZE )
        return EXIT_FAILURE;

	memcpy(twk, sector_address, AES_BLOCK_SIZE);
    aes_encrypt(UPTR_CAST(twk, 8), UPTR_CAST(twk, 8), ctx->twk_ctx);

    while(pos + AES_BLOCK_SIZE <= hi_byte)
    {
        f_ptr(pos, pos, twk);
        aes_encrypt(pos, pos, ctx->enc_ctx);
        f_ptr(pos, pos, twk);
        pos += AES_BLOCK_SIZE;
        gf_mulx(twk);
    }

    if(pos < hi)
    {
        uint8_t *lb = pos - AES_BLOCK_SIZE, *tp = lb;
        while(pos < hi)
        {
            uint8_t tt = *lb;
            *lb++ = *pos;
            *pos++ = tt;
        }

		if(bits)
		{
			uint8_t mask = ~(0xff >> bits);

			*--lb &= mask;
			*lb |= (*--pos) & ~mask;
			*pos &= mask;
		}
        f_ptr(tp, tp, twk);
        aes_encrypt(tp, tp, ctx->enc_ctx);
        f_ptr(tp, tp, twk);
    }
    return EXIT_SUCCESS;
}

INT_RETURN xts_decrypt( unsigned char sector[], unsigned int sector_len_bits,
						unsigned char sector_address[], const xts_ctx ctx[1] )
{   
    buf_type twk, twk2;
	uint8_t bits = sector_len_bits & 7;
	uint8_t *pos = sector, *hi = pos + ((sector_len_bits + 7) >> 3),
		    *hi_byte = pos + (sector_len_bits >> 3);

    xor_function f_ptr = (!ALIGN_OFFSET(sector, UNIT_BITS >> 3) ? xor_block_aligned : xor_block );

    if( sector_len_bits < 8 * AES_BLOCK_SIZE )
        return EXIT_FAILURE;

	memcpy(twk, sector_address, AES_BLOCK_SIZE);
    aes_encrypt(UPTR_CAST(twk, 8), UPTR_CAST(twk, 8), ctx->twk_ctx);

    while(pos + AES_BLOCK_SIZE <= hi_byte)
    {
		if(pos + 2 * AES_BLOCK_SIZE > hi_byte && pos + AES_BLOCK_SIZE < hi)
        {
            memcpy(twk2, twk, AES_BLOCK_SIZE);
            gf_mulx(twk);
        }
        f_ptr(pos, pos, twk);
        aes_decrypt(pos, pos, ctx->dec_ctx);
        f_ptr(pos, pos, twk);
        pos += AES_BLOCK_SIZE;
        gf_mulx(twk);
    }

    if(pos < hi)
    {
        uint8_t *lb = pos - AES_BLOCK_SIZE, *tp = lb;
        while(pos < hi)
        {
            uint8_t tt = *lb;
            *lb++ = *pos;
            *pos++ = tt;
        }
		if(bits)
		{
			uint8_t mask = ~(0xff >> bits);

			*--lb &= mask;
			*lb |= (*--pos) & ~mask;
			*pos &= mask;
		}
		f_ptr(tp, tp, twk2);
        aes_decrypt(tp, tp, ctx->dec_ctx);
        f_ptr(tp, tp, twk2);
    }

    return EXIT_SUCCESS;
}
