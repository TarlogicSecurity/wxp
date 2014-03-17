/* 
 * wxp_send.c: PDU send functions.
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

static char *pktypes[] = {"NULL  ", "DATA  ", "ACK   ", "RST   ", "REPEAT", "SYN   ", "SYNACK"};

int
wxp_send_pdu (p_wxp_state_t state, p_wxp_pdu_t pdu, size_t size)
{
	pdu->checksum = htonl (0);
	pdu->sessid   = htonl (state->sessid);
	pdu->scramble = wxp_random ();
	pdu->checksum = htonl (wxp_calc_checksum (pdu, size));

	wxpdbg (WXPDBG_SEND, "[%s] sessid=%08x, seq/count/new_sessid=%08x, size=%d\n", pktypes[ntohs (pdu->type)], ntohl (pdu->sessid), ntohl (pdu->new_sessid), size); 

	return ((wxp_get_current_backend ())->sendto) (wxp_get_current_backend_data (), state->src, state->dst, pdu, size);
}

/* The following functions cannot use wxp_send_pdu as there's no session yet */
int
wxp_send_syn (wxp_addr_t src, wxp_addr_t dst, uint32_t init_sessid)
{
	wxp_pdu_t pdu;

	memset (&pdu, 0, sizeof (wxp_pdu_t));

	pdu.type     = htons (WXP_TYPE_SYN);
	pdu.sessid   = htonl (init_sessid);
	pdu.scramble = wxp_random ();
	pdu.checksum = htonl (wxp_calc_checksum (&pdu, sizeof (wxp_pdu_t)));

	wxpdbg (WXPDBG_SEND, "[%s] sessid=%08x, seq/count/new_sessid=%08x, size=%d\n", pktypes[ntohs (pdu.type)], ntohl (pdu.sessid), ntohl (pdu.new_sessid), sizeof (wxp_pdu_t)); 

	return ((wxp_get_current_backend ())->sendto) (wxp_get_current_backend_data (), src, dst, &pdu, sizeof (wxp_pdu_t));
}

/* This RST is sent when rejecting a session */
int
wxp_send_rst (wxp_addr_t src, wxp_addr_t dst, uint32_t init_sessid, uint16_t seq)
{
	wxp_pdu_t pdu;

	memset (&pdu, 0, sizeof (wxp_pdu_t)); /* Sent with seq = 0 */

	pdu.type     = htons (WXP_TYPE_RST);
	pdu.sessid   = htonl (init_sessid);
	pdu.seq      = htons (seq);
	pdu.scramble = wxp_random ();

	pdu.checksum = htonl (wxp_calc_checksum (&pdu, sizeof (wxp_pdu_t)));

	wxpdbg (WXPDBG_SEND, "[%s] sessid=%08x, seq/count/new_sessid=%08x, size=%d\n", pktypes[ntohs (pdu.type)], ntohl (pdu.sessid), ntohl (pdu.new_sessid), sizeof (wxp_pdu_t)); 

	return ((wxp_get_current_backend ())->sendto) (wxp_get_current_backend_data (), src, dst, &pdu, sizeof (wxp_pdu_t));
}

int
wxp_send_synack (wxp_addr_t src, wxp_addr_t dst, uint32_t init_sessid, uint32_t new_sessid)
{
	wxp_pdu_t pdu;

	memset (&pdu, 0, sizeof (wxp_pdu_t));

	pdu.type       = htons (WXP_TYPE_SYNACK);
	pdu.sessid     = htonl (init_sessid);
	pdu.new_sessid = htonl (new_sessid);
	pdu.scramble   = wxp_random ();
	pdu.checksum   = htonl (wxp_calc_checksum (&pdu, sizeof (wxp_pdu_t)));

	wxpdbg (WXPDBG_SEND, "[%s] sessid=%08x, seq/count/new_sessid=%08x, size=%d\n", pktypes[ntohs (pdu.type)], ntohl (pdu.sessid), ntohl (pdu.new_sessid), sizeof (wxp_pdu_t)); 

	return ((wxp_get_current_backend ())->sendto) (wxp_get_current_backend_data (), src, dst, &pdu, sizeof (wxp_pdu_t));
}

int
wxp_send_ack (wxp_addr_t src, wxp_addr_t dst, uint32_t sessid)
{
	wxp_pdu_t pdu;

	memset (&pdu, 0, sizeof (wxp_pdu_t));

	pdu.type     = htons (WXP_TYPE_ACK);
	pdu.sessid   = htonl (sessid);
	pdu.scramble = wxp_random ();
	pdu.checksum = htonl (wxp_calc_checksum (&pdu, sizeof (wxp_pdu_t)));

	wxpdbg (WXPDBG_SEND, "[%s] sessid=%08x, seq/count/new_sessid=%08x, size=%d\n", pktypes[ntohs (pdu.type)], ntohl (pdu.sessid), ntohl (pdu.new_sessid), sizeof (wxp_pdu_t)); 

	return ((wxp_get_current_backend ())->sendto) (wxp_get_current_backend_data (), src, dst, &pdu, sizeof (wxp_pdu_t));
}
