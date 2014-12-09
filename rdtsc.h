/*
---------------------------------------------------------------------------
Copyright (c) 1998-2010, Brian Gladman, Worcester, UK. All rights reserved.

The redistribution and use of this software (with or without changes)
is allowed without the payment of fees or royalties provided that:

  source code distributions include the above copyright notice, this
  list of conditions and the following disclaimer;

  binary distributions include the above copyright notice, this list
  of conditions and the following disclaimer in their documentation.

This software is provided 'as is' with no explicit or implied warranties
in respect of its operation, including, but not limited to, correctness
and fitness for purpose.
---------------------------------------------------------------------------
Issue Date: 20/12/2007
*/

#ifndef RDTSC_H
#define RDTSC_H

#if defined( _WIN32 ) || defined( _WIN64 )

#   include <intrin.h>
#   pragma intrinsic( __rdtsc )

    __inline volatile unsigned long long read_tsc(void)
    {
        return __rdtsc();
    }

#elif defined( __GNUC__ )

    static inline volatile unsigned long long read_tsc(void)
    {
        unsigned long lo, hi;
        asm volatile("cpuid; rdtsc" : "=a" (lo), "=d" (hi));
        return (((unsigned long long)hi) << 32) + lo;
    }
#else
#   error A high resolution timer is not available
#endif

#endif
