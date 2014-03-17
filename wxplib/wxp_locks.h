/* 
 * wxp_locks.h: prototypes and definition for synchronization mechanisms.
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
#ifndef _WXP_WXP_LOCKS_H
#define _WXP_WXP_LOCKS_H

#include "wxp_state.h"

void wxp_server_state_lock (void);
void wxp_server_state_unlock (void);

void wxp_global_state_lock (void);
void wxp_global_state_unlock (void);

void wxp_ack_queue_lock (p_wxp_state_t);
void wxp_ack_queue_unlock (p_wxp_state_t);

void wxp_signal_new_state (void);
int  wxp_wait_for_event (void);

int wxp_wait_for_sender_event (p_wxp_state_t);
int wxp_wait_connection_completion (p_wxp_state_t);

void wxp_signal_connection_completion (p_wxp_state_t);
void wxp_signal_new_connection (void);

void wxp_wait_new_connection (void);
int wxp_sender_event_is_signaled (p_wxp_state_t, int);

void wxp_wait_hysteresis (p_wxp_state_t);
void wxp_signal_hysteresis (p_wxp_state_t);
void wxp_wait_disposal (p_wxp_state_t);
void wxp_signal_disposal (p_wxp_state_t);
int wxp_init_locks (const p_wxp_backend_t, void *);

#endif  /* _WXP_WXP_LOCKS_H */
