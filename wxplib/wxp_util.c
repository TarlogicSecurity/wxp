/* 
 * wxp_util.c: common utility functions.
 */
/*
	Copyright (c) 2014, Tarlogic Security
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:
	1. Redistributions of source code must retain the above copyright
	   notice, this list of conditions and the following disclaimer.
	2. Redistributions in binary form must reproduce the above copyright
	   notice, this list of conditions and the following disclaimer in the
	   documentation and/or other materials provided with the distribution.
	3. All advertising materials mentioning features or use of this software
	   must display the following acknowledgement:
	   This product includes software developed by Tarlogic Security.
	4. Neither the name of the Tarlogic Security nor the
	   names of its contributors may be used to endorse or promote products
	   derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY TARLOGIC SECURITY ''AS IS'' AND ANY
	EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL TARLOGIC SECURITY BE LIABLE FOR ANY
	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "wxp_state.h"

#include <string.h>
#include <stdlib.h>

int
wxp_addrcmp (const wxp_addr_t *addr1, const wxp_addr_t *addr2)
{
	if (addr1->addrlen != addr2->addrlen)
		return addr1->addrlen - addr2->addrlen;

	return memcmp (addr1->addrdata, addr2->addrdata, addr1->addrlen);
}

uint32_t
wxp_calc_checksum (const void *buf, size_t size)
{
	unsigned int num, i;
	uint32_t result = 0;

	const uint16_t *words = (const uint16_t *) buf;
	num = size >> 2;

	for (i = 0; i < num; ++i)
		result += ntohs (words[i]);

	if (size & 1)
		result += *((const uint8_t *) buf + size - 1);

	return ~result;
}

BOOL initialized;
uint32_t last_seed;

#ifdef _WIN32
HANDLE randmutex;
#endif

uint32_t
wxp_random (void)
{
	if (!initialized)
	{
		randmutex = CreateMutex (NULL, FALSE, NULL);
		last_seed = (uint32_t) wxp_get_timestamp ();
		srand (last_seed * GetCurrentProcessId ());
		initialized = TRUE;
	}

	WaitForSingleObject (randmutex, INFINITE);

	last_seed = (rand () << 16) ^ rand ();

	ReleaseMutex (randmutex);

	return last_seed;
}
