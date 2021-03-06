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
 Issue Date: 11/10/2008
*/

#include <iomanip>
#include <new>

#include "testvec.h"
#include "eme2.h"

const char *t_name[] = {
	"KEY", "ADT", "PTX", "CTX", "VEC", "GEN", "END"
};
const size_t t_length = sizeof(t_name) / sizeof(t_name[0]);

#define MAX_BLOCK_SIZE  5120
#define BLOCK_SIZE      AES_BLOCK_SIZE

void do_test(const char *in_dir, const char *out_dir, const char *name, int gen_flag)
{
	std::string     line, f_name("EME2");
	int64_t			i, err = -1, v_err = -1, file_no = 0, vec_no, vec_count;
	test_vec		v;
	std::fstream    inf, outf;
	char			ext[3] = { '.', '0', '\0' };

	for( ; ; )
	{
		++file_no;
		if(!open_files(inf, outf, std::string(in_dir), std::string(out_dir),
			f_name, file_no, gen_flag))
			break;

		vec_count = v_err = 0;
		for( ; ; )
		{
			if(!input_vector(inf, v, &vec_no, outf, gen_flag))
				break;
			++vec_count;
			err = 0;

			size_t key_len, adt_len, ptx_len, ctx_len;
			int64_t adt_rpt, ptx_rpt;

			const uint8_t * const key = v.get_value("KEY", &key_len);
			const uint8_t * const adt = v.get_value("ADT", &adt_len, &adt_rpt);
			const uint8_t * const ptx = v.get_value("PTX", &ptx_len, &ptx_rpt);
			const uint8_t * const ctx = v.get_value("CTX", &ctx_len);

            i = ptx_rpt;
            while(i--)
            {   
				uint8_t *res = new uint8_t[ptx_len];
                memcpy(res, ptx, ptx_len);
                if(eme2_encrypt( res, res, ptx_len, adt, adt_len, (eme2_key*)key, key_len) != EXIT_SUCCESS)
                    err |= 1;
                if(memcmp(ctx, res, ptx_len))
                {
					std::cout << std::endl << "\tencrypt error on test number ", vec_no;
					err += 4;
                    break;
                }

                if(eme2_decrypt( res, res, ptx_len, adt, adt_len, (eme2_key*)key, key_len) != EXIT_SUCCESS)
                    err |= 2;
                if(memcmp(ptx, res, ptx_len))
                {
					std::cout << std::endl << "\tdecrypt error on test number ", vec_no;
					err += 4;
                    break;
                }
				delete[]res;
            }
			if(gen_flag)
				v.vector_out(outf, vec_no);
			if(err)
			  ++v_err;
		}
		inf.close();
		if (gen_flag && !v_err)
		{
			outf << std::endl << "END " << std::endl;
			outf.close();
		}
		if(v_err == 0)
			std::cout << ": all " << vec_count << " vectors matched";
		else if(v_err > 0)
			std::cout << std::endl << v_err << " errors in " << vec_no << " vectors";
		else
			std::cout << ": test vector file(s) not found";
    }
    return;
}

int main(int argc, char *argv[])
{
	if(argc == 4)
		do_test(argv[1], argv[2], argv[3], 1);
	else
		std::cout << std::endl << "usage: input_directory output_directory mode_name";
	std::cout << std::endl << std::endl;
    return 0;
}
