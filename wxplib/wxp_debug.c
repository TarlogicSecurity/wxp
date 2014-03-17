/* 
 * wxp_debug.c: debug functions.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "wxp_state.h"


BOOL
wxp_debugmessagetype_enabled (int type)
{
	if (type < 0 || type > 7)
		return FALSE;

	 /* type == WXPDBG_SEND || type == WXPDBG_RECV || type == WXPDBG_QUEUES || type == WXPDBG_ACK */
	return FALSE;  
}

void
wxpdbg (int type, const char *fmt, ...)
{
	char *types[] = {"QUEUES",
		             "<---- ",
					 " ---->", 
					 "ACK   ",
					 "REP   ",
					 "SESS  ",
					 "EVENT ",
					 "API   "};

	va_list ap;

	va_start (ap, fmt);

	if (wxp_debugmessagetype_enabled (type))
	{
		fprintf (stderr, "[WXP:%s] ", types[type]);
		
		vfprintf (stderr, fmt, ap);
	}

	va_end (ap);
}
