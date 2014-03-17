/* 
 * wxp_tx_thread.c: transmission thread, each state has its own instance.
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
#include "wxp_locks.h"

#include <stdio.h>

static void
wxp_fill_seq_cb (void *data, struct qel *qel)
{
	struct array_header *hdr = (struct array_header *) data;

	hdr->seq[hdr->count++] = ntohs (((p_wxp_pdu_t) qel->data)->seq);
}

static int
__compare_uint16 (const void *a, const void *b)
{
	return (int) *(uint16_t *) a - (int) *(uint16_t *) b;
}

static int
wxp_send_pending_acks (p_wxp_state_t state)
{
	int         result = 0;
	char        resp_pdu_buffer[sizeof (wxp_pdu_t) + WXP_ACK_PDU_MAX_ENTRIES * sizeof (uint16_t)];
	p_wxp_pdu_t resp_pdu_hdr = (p_wxp_pdu_t) resp_pdu_buffer;
	uint16_t   *seqs = (uint16_t *) resp_pdu_hdr->count;
	p_wxp_pdu_t pdu_hdr;
	size_t      pdu_size;
	int         i;

	wxp_ack_queue_lock (state);

	resp_pdu_hdr->type   = htons (WXP_TYPE_ACK);
	resp_pdu_hdr->sessid = htonl (state->sessid);

	do
	{
		seqs = (uint16_t *) resp_pdu_hdr->data;

		for (i = 0; i < WXP_ACK_PDU_MAX_ENTRIES; ++i)
			if (packet_queue_pick (state->ack_queue, (void **) &pdu_hdr, &pdu_size) != -1)
			{
				seqs[i] = pdu_hdr->seq;
				free (pdu_hdr);
			}
			else
				break;
			
		resp_pdu_hdr->count = htons (i);

		if (i > 0)
		{
			wxpdbg (WXPDBG_SEND, "Send pending acks: %d acks (%d bytes)\n", i, sizeof (wxp_pdu_t) + i * sizeof (uint16_t));
			result = wxp_send_pdu (state, resp_pdu_hdr, sizeof (wxp_pdu_t) + i * sizeof (uint16_t));
		}

		if (result == -1)
			break;
	}
	while (i > 0);

	wxp_ack_queue_unlock (state);

	return result;
}


static int
wxp_ask_for_lost (p_wxp_state_t state)
{
	int         result = 0;
	char        resp_pdu_buffer[sizeof (wxp_pdu_t) + WXP_ACK_PDU_MAX_ENTRIES * sizeof (uint16_t)];
	p_wxp_pdu_t resp_pdu_hdr = (p_wxp_pdu_t) resp_pdu_buffer;
	uint16_t   *seqs = (uint16_t *) resp_pdu_hdr->count;
	struct array_header seqlist;
	uint16_t prev_seq;
	int n, i;

	wxp_queue_lock_object (state->queues, WXP_OBJECT_INCOMING_QUEUE);

	if (state->queues->incoming_q->count > 0)
	{
		resp_pdu_hdr->type   = htons (WXP_TYPE_REPEAT);
		resp_pdu_hdr->sessid = htonl (state->sessid);

		seqlist.count = 0;
		seqs = (uint16_t *) resp_pdu_hdr->data;

		/* TODO: add something like get_queue_size */
		if ((seqlist.seq = (uint16_t *) calloc (state->queues->incoming_q->count, sizeof (uint16_t))) == NULL)
			return -1;

		packet_queue_walk (state->queues->incoming_q, wxp_fill_seq_cb, &seqlist);

		assert (state->queues->incoming_q->count == seqlist.count);

		/* Not necessary from now on. REMOVE!!! */
		qsort (seqlist.seq, seqlist.count, sizeof (uint16_t), __compare_uint16);

		prev_seq = state->queues->in_curr_seq;

		n = i = 0;

		while (i < seqlist.count && n < WXP_REP_PDU_MAX_ENTRIES)
		{
			while (n < WXP_REP_PDU_MAX_ENTRIES && prev_seq < seqlist.seq[i])
			{
				wxpdbg (WXPDBG_REP, "Asking for lost packet %d\n", prev_seq);
				seqs[n++] = htons (prev_seq++);
			}

			++prev_seq;
			++i;
		}
		
		resp_pdu_hdr->count = htons (n);

		if (n > 0)
			result = wxp_send_pdu (state, resp_pdu_hdr, sizeof (wxp_pdu_t) + n * sizeof (uint16_t));

		free (seqlist.seq);

		wxp_sched_lost (state);
	}

	wxp_queue_unlock_object (state->queues, WXP_OBJECT_INCOMING_QUEUE);

	return result;
}

static void
wxp_repeat_cb (void *data, struct qel *qel)
{
	p_wxp_ack_header_t hdr = (p_wxp_ack_header_t) qel->data;
	p_wxp_state_t state = (p_wxp_state_t) data;
	p_wxp_pdu_t pdu = (p_wxp_pdu_t) hdr->data;
	BOOL confirmed;

	wxp_queue_lock_object (state->queues, WXP_OBJECT_OUTCOMING_QUEUE);

	confirmed = wxp_seq_already_confirmed (state, ntohs (pdu->seq));

	wxp_queue_unlock_object (state->queues, WXP_OBJECT_OUTCOMING_QUEUE);

	if (confirmed)
		wxpdbg (WXPDBG_ACK, "Sessid: %08x: Packet %d already confirmed\n", state->sessid, ntohs (pdu->seq));

	if (((wxp_get_timestamp () - hdr->timestamp) > WXP_DEFAULT_REPEAT_TIMEOUT || hdr->retry_count == 0) && !confirmed)
	{
		if (++hdr->retry_count > WXP_MAX_RETRY)
		{
			wxp_state_set_waitkill (state, WXP_REASON_ACK_TIMEOUT);

			wxp_signal_new_state ();
	
			return;
		}

		hdr->timestamp = wxp_get_timestamp ();

		(void) wxp_send_pdu (state, (p_wxp_pdu_t) hdr->data, qel->size - sizeof (wxp_ack_header_t));

		wxpdbg (WXPDBG_REP, "Sessid %p: Repeated packet %d for %dth time, %d elements in queue\n", state->sessid, ntohs (((p_wxp_pdu_t) hdr->data)->seq), hdr->retry_count, state->queues->outcoming_q->count);
	}
}

static void
wxp_repeat_all_unconfirmed (p_wxp_state_t state)
{
	struct packet_queue *tmp;
	struct qel *curr;

	if ((tmp = packet_queue_new ()) == NULL)
		return;

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;;;                                                                          ;;;
	;;; wxp_queue_lock_object (state->queues, WXP_OBJECT_OUTCOMING_QUEUE);       ;;;
	

	curr = state->queues->outcoming_q->head;

	while (curr)
	{
		(void) packet_queue_put (tmp, curr->data, curr->size);
		curr = curr->next;
	}

	;;; wxp_queue_unlock_object (state->queues, WXP_OBJECT_OUTCOMING_QUEUE);     ;;;
	;;;                                                                          ;;;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


	wxpdbg (WXPDBG_REP, "Repeating whole session %p...\n", state->sessid);

	packet_queue_walk (tmp, wxp_repeat_cb, state);

	wxpdbg (WXPDBG_REP, "Session %p finished repeating\n", state->sessid);

	packet_queue_destroy (tmp);
}

int
wxp_sender_thread (p_wxp_state_t state)
{	
	p_wxp_pdu_t pdu_hdr;
	size_t      pdu_size;

	int result = 0;

	for (;;)
	{
		
		result = wxp_wait_for_sender_event (state);


		wxpdbg (WXPDBG_EVENT, "%p: Sender event %d\n", state->sessid, result);

		if (state->wait_kill)
		{
			wxpdbg (WXPDBG_SESS, "Sender thread of %08x: wait kill!\n", state->sessid);
			break;
		}

		switch (result)
		{
		case WXP_SENDER_EVENT_SEND:
			while (wxp_out_queue_pick (state->queues, &pdu_hdr, &pdu_size) != -1)
			{
				if (wxp_sender_event_is_signaled (state, WXP_SENDER_EVENT_ACK))
					wxp_send_pending_acks (state);

				if ((result = wxp_send_pdu (state, pdu_hdr, pdu_size)) == -1)
					break;
			}

			wxp_sched_repeat_periodically (state);
			/*wxp_sched_send_periodically (state);*/

			wxpdbg (WXPDBG_QUEUES, "Queues %08x (outcoming_seq: %d)\n", state->sessid, state->queues->out_curr_seq);
			wxpdbg (WXPDBG_QUEUES, "   Input queue size: %d\n", state->queues->input_q->count);
			wxpdbg (WXPDBG_QUEUES, "   Output queue size: %d\n", state->queues->output_q->count);
			wxpdbg (WXPDBG_QUEUES, "   Incoming queue size: %d\n", state->queues->incoming_q->count);
			wxpdbg (WXPDBG_QUEUES, "   Outcoming queue size: %d\n", state->queues->outcoming_q->count);

			break;

		case WXP_SENDER_EVENT_ACK:
			result = wxp_send_pending_acks (state);

			break;

		case WXP_SENDER_EVENT_REPEAT:
			if (!state->connected)
			{
				wxpdbg (WXPDBG_REP, "Repeat SYNACK (sessid %p)...\n", state->sessid);
				result = wxp_send_synack (state->src, state->dst, state->suggested_sessid, state->sessid);
			}
			else
			{
				if (state->queues->outcoming_q->count)
				{
					wxpdbg (WXPDBG_REP, "%p: Repeating %d in outcoming (%p:%p)...\n", state->sessid, state->queues->outcoming_q->count, state->queues->outcoming_q->head, state->queues->outcoming_q->tail);
					wxpdbg (WXPDBG_ACK, "Repeat: %08x: state: %p, queues: %p\n", state->sessid, state, state->queues);
				}

				wxp_repeat_all_unconfirmed (state);

				wxp_sched_repeat_periodically (state);
			}

			break;

		case WXP_SENDER_EVENT_LOST:
			result = wxp_ask_for_lost (state);

			break;
		}

		if (result == -1)
		{
			wxp_state_set_waitkill (state, WXP_REASON_INTERNAL_ERROR);
			wxp_signal_new_state ();

			break;
		}
	}

	return result;
}

/* Sender event scheduling functions */
int
wxp_sched_ack (p_wxp_state_t state, const p_wxp_pdu_t pdu)
{
	int result;

	wxpdbg (WXPDBG_EVENT, "%p: sched ack\n", state->sessid);

	wxp_ack_queue_lock (state);

	result = packet_queue_put (state->ack_queue, pdu, sizeof (wxp_pdu_t)); /* We save just the header */

	wxp_ack_queue_unlock (state);

#ifdef _WIN32
	if (!state->hAckQueueEventDue.QuadPart)
	{
		state->hAckQueueEventDue.QuadPart = -WXP_ACK_QUEUE_SLEEP * 10000ll;
	
		if (!SetWaitableTimer (state->hAckQueueEvent, &state->hAckQueueEventDue, 0, NULL, NULL, FALSE))
			return -1;
	}
	else
		wxpdbg (WXPDBG_EVENT, "%p: ack: timer in progress\n", state->sessid);
#endif

	return 0;
}

int
wxp_sched_repeat (p_wxp_state_t state)
{
	wxpdbg (WXPDBG_EVENT, "%p: sched repeat\n", state->sessid);
#ifdef _WIN32
	
	if (-state->hRepeatEventDue.QuadPart > WXP_REP_QUEUE_SLEEP * 10000ll || !state->hRepeatEventDue.QuadPart)
	{
		state->hRepeatEventDue.QuadPart = -WXP_REP_QUEUE_SLEEP * 10000ll;

		if (!SetWaitableTimer (state->hRepeatEvent, &state->hRepeatEventDue, 0, NULL, NULL, FALSE))
			return -1;
	}
	else
		wxpdbg (WXPDBG_EVENT, "%p: repeat: timer in progress (%lli * 100ns)\n", state->sessid, state->hRepeatEventDue.QuadPart);

	return 0;
#endif
}

int
wxp_sched_repeat_periodically (p_wxp_state_t state)
{
	wxpdbg (WXPDBG_EVENT, "%p: sched repeat (periodically)\n", state->sessid);

#ifdef _WIN32
	if (-state->hRepeatEventDue.QuadPart > WXP_REPEAT_CHECK_PERIOD * 10000ll || !state->hRepeatEventDue.QuadPart)
	{
		state->hRepeatEventDue.QuadPart = -WXP_REPEAT_CHECK_PERIOD * 10000ll;

		if (!SetWaitableTimer (state->hRepeatEvent, &state->hRepeatEventDue, 0, NULL, NULL, FALSE))
			return -1;
	}
	else
		wxpdbg (WXPDBG_EVENT, "%p: repeat periodically: timer in progress (%lli * 100ns)\n", state->sessid, state->hRepeatEventDue.QuadPart);

	return 0;
#endif
}

int
wxp_sched_lost (p_wxp_state_t state)
{
	wxpdbg (WXPDBG_EVENT, "%p: sched lost\n", state->sessid);

#ifdef _WIN32
	if (!state->hLostEventDue.QuadPart)
	{
		state->hLostEventDue.QuadPart = -WXP_LOST_QUEUE_SLEEP * 10000ll;

		if (!SetWaitableTimer (state->hLostEvent, &state->hLostEventDue, 0, NULL, NULL, FALSE))
			return -1;

		wxpdbg (WXPDBG_EVENT, "Repeat packet scheduled for %dms\n", WXP_LOST_QUEUE_SLEEP);
	}
	else
		wxpdbg (WXPDBG_EVENT, "%p: lost: timer in progress\n", state->sessid);

	return 0;
#endif
}

int
wxp_sched_send (p_wxp_state_t state)
{
	wxpdbg (WXPDBG_EVENT, "%p: sched send\n", state->sessid);

#ifdef _WIN32
	if (!state->hSendEventDue.QuadPart)
	{
		state->hSendEventDue.QuadPart = -WXP_OUT_QUEUE_SLEEP * 10000ll;

		if (!SetWaitableTimer (state->hSendEvent, &state->hSendEventDue, 0, NULL, NULL, FALSE))
			return -1;
	}
	else
	{
		printf ("CANNOT!\n");
		wxpdbg (WXPDBG_EVENT, "%p: repeat: timer in progress\n", state->sessid);
	}

	return 0;
#endif
}

int
wxp_sched_send_periodically (p_wxp_state_t state)
{
	wxpdbg (WXPDBG_EVENT, "%p: sched send (periodically)\n", state->sessid);

#ifdef _WIN32
	if (!state->hSendEventDue.QuadPart)
	{
		state->hSendEventDue.QuadPart = -WXP_SEND_CHECK_PERIOD * 10000ll;

		if (!SetWaitableTimer (state->hSendEvent, &state->hSendEventDue, 0, NULL, NULL, FALSE))
			return -1;
	}
	else
		wxpdbg (WXPDBG_EVENT, "%p: send periodically: timer in progress\n", state->sessid);

	return 0;
#endif
}

