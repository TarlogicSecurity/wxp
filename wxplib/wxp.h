/* 
 * wxp.h: main include file for the WXP library.
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

#ifndef _WXP_WXP_H
#define _WXP_WXP_H

#include "wxp_state.h"

#ifdef __cplusplus
extern "C"
{
#endif
/* Library init */
int           wxp_init    (wxp_addr_t, const p_wxp_backend_t, void *);

/* Connection establishment functions */
p_wxp_state_t wxp_listen  (wxp_addr_t);
p_wxp_state_t wxp_connect (wxp_addr_t);

/* Data transfer functions. NOTE: this functions are not thread-safe.
   You should use a mutex if you plan to use them in several threads. */
int           wxp_read    (p_wxp_state_t, void *, size_t);
int           wxp_write   (p_wxp_state_t, const void *, size_t);

/* Close a connection */
int           wxp_close   (p_wxp_state_t);

#ifdef __cplusplus
}
#endif

#endif /* _WXP_WXP_H */
