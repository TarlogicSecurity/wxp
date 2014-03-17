/* 
 * wxp_state.c: WXP connection state and main API functions.
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


#include "wxp.h"
#include "wxp_locks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static p_wxp_backend_t current_backend;
static void *current_backend_data;
wxp_addr_t   current_remote_address;


p_wxp_state_t *wxp_state_list;
unsigned int   wxp_state_count;

p_wxp_state_t *wxp_listening_list;
unsigned int   wxp_listening_count;
unsigned int   wxp_listening_max;

p_wxp_state_t
wxp_get_listening_state (uint32_t sessid)
{
	unsigned int i;
	p_wxp_state_t result = NULL;

	wxp_server_state_lock ();

	for (i = 0; i < wxp_listening_count; ++i)
		if (wxp_listening_list[i] != NULL)
			if (wxp_listening_list[i]->sessid == sessid)
			{
				result = wxp_listening_list[i];
				break;
			}

	wxp_server_state_unlock ();
	
	return result;
}

p_wxp_state_t
wxp_pull_listening_state (void)
{
	unsigned int i;
	p_wxp_state_t result = NULL;

	wxp_server_state_lock ();

	for (i = 0; i < wxp_listening_count; ++i)
		if (wxp_listening_list[i] != NULL)
			if (wxp_listening_list[i]->connected)
			{
				result = wxp_listening_list[i];
				wxp_listening_list[i] = NULL;
				break;
			}

	wxp_server_state_unlock ();
	
	return result;
}

p_wxp_state_t
wxp_get_listening_state_by_suggested_sessid (uint32_t suggested_sessid)
{
	unsigned int i;
	p_wxp_state_t result = NULL;

	wxp_server_state_lock ();

	for (i = 0; i < wxp_listening_count; ++i)
		if (wxp_listening_list[i] != NULL)
			if (wxp_listening_list[i]->suggested_sessid == suggested_sessid)
			{
				result = wxp_listening_list[i];
				break;
			}

	wxp_server_state_unlock ();
	
	return result;
}

void
wxp_cleanup_expired_listening_states (void)
{
	unsigned int i;
	wxp_server_state_lock ();

	for (i = 0; i < wxp_listening_count; ++i)
		if (wxp_listening_list[i] != NULL)
			if ((wxp_get_timestamp () - wxp_listening_list[i]->first_syn_timestamp) > WXP_DEFAULT_SYNACK_TIMEOUT)
			{
				wxpdbg (WXPDBG_SESS, "Cleaning up listening state %08x (expired after %lldms with no ACK)\n", wxp_listening_list[i]->sessid, (wxp_get_timestamp () - wxp_listening_list[i]->first_syn_timestamp));

				wxp_state_set_waitkill (wxp_listening_list[i], WXP_REASON_CONNECTION_TIMEOUT);
				
				wxp_clear_waitkill_states ();

				/* We can do this as only the receiver thread knows about this state */
				wxp_state_destroy (wxp_listening_list[i]);

				wxp_listening_list[i] = NULL;

				break;
			}

	wxp_server_state_unlock ();
}

int
wxp_push_listening_state (p_wxp_state_t state)
{
	unsigned int i;
	p_wxp_state_t *tmp;

	wxp_server_state_lock ();

	for (i = 0; i < wxp_listening_count; ++i)
		if (wxp_listening_list[i] == NULL)
			break;

	if (wxp_listening_count == wxp_listening_max)
	{
		wxp_server_state_unlock ();

		return -1;
	}

	if (i == wxp_listening_count)
	{
		if ((tmp = (p_wxp_state_t *) realloc (wxp_listening_list, (wxp_listening_count + 1) * sizeof (p_wxp_state_t))) == NULL)
		{
			wxp_server_state_unlock ();

			return -1;
		}

		wxp_listening_list = tmp;
		++wxp_listening_count;
	}

	wxp_listening_list[i] = state;

	wxp_server_state_unlock ();

	return 0;
}

int
wxp_init (wxp_addr_t remote_addr, const p_wxp_backend_t backend, void *backend_data)
{
	if (current_backend != NULL)
		return -1;

	if (wxp_init_locks (backend, backend_data) == -1)
		return -1;

	current_backend = backend;
	current_backend_data = backend_data;
	current_remote_address = remote_addr;
	wxp_listening_max = WXP_DEFINE_LISTEN_QUEUE_SIZE;

	return 0;
}

void
wxp_state_set_waitkill (p_wxp_state_t state, wxp_close_reason_t reason)
{
	if (!state->wait_kill)
	{
		state->wait_kill = TRUE;
		state->kill_reason = reason;

		state->queues->dead = TRUE;

		wxp_signal_object (state->queues, WXP_OBJECT_INPUT_QUEUE);
	}
}

p_wxp_backend_t
wxp_get_current_backend (void)
{
	return current_backend;
}

void *
wxp_get_current_backend_data (void)
{
	return current_backend_data;
}

wxp_addr_t
wxp_get_current_remote_address (void)
{
	return current_remote_address;
}

#ifdef _WIN32
static DWORD WINAPI
SenderThreadFunc (LPVOID data)
{
	p_wxp_state_t state = (p_wxp_state_t) data;

	wxp_sender_thread (state);

	return -1;
}
#endif

p_wxp_state_t
wxp_state_new (void)
{
	p_wxp_state_t state;

	if ((state = (p_wxp_state_t) calloc (1, sizeof (wxp_state_t))) == NULL)
		return NULL;

	if ((state->queues = wxp_queue_new ()) == NULL)
		goto FAIL_MISERABLY;

	if ((state->ack_queue = packet_queue_new ()) == NULL)
		goto FAIL_MISERABLY;

	state->hysteresis_threshold_lock   = WXP_DEFAULT_LOCK_THRESHOLD;
	state->hysteresis_threshold_unlock = WXP_DEFAULT_UNLOCK_THRESHOLD;

#ifdef _WIN32
	if ((state->hAckQueueMutex   = CreateMutex (NULL, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((state->hSendEvent       = CreateWaitableTimer (NULL, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((state->hAckQueueEvent   = CreateWaitableTimer (NULL, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((state->hRepeatEvent     = CreateWaitableTimer (NULL, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((state->hLostEvent       = CreateWaitableTimer (NULL, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((state->hConnectionEvent = CreateEvent (NULL, FALSE, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((state->hHysterEvent     = CreateEvent (NULL, FALSE, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((state->hCloseEvent      = CreateEvent (NULL, FALSE, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((state->hDisposeEvent    = CreateEvent (NULL, FALSE, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((state->hSenderThread    = CreateThread (NULL, 0, SenderThreadFunc, state, 0, &state->dwSenderThreadId)) == NULL)
		goto FAIL_MISERABLY;
#endif

	return state;

FAIL_MISERABLY:
	wxp_state_destroy (state);

	return NULL;
}

void
wxp_state_clear (p_wxp_state_t state)
{
	wxp_state_set_waitkill (state, WXP_REASON_STATE_CLEARED);

#ifdef _WIN32
	wxp_queue_destroy_mutexes (state->queues);

	if (state->hCloseEvent != NULL)
	{
		CloseHandle (state->hCloseEvent);
		state->hCloseEvent = INVALID_HANDLE_VALUE;
	}

	if (state->hAckQueueMutex != NULL)
	{
		CloseHandle (state->hAckQueueMutex);
		state->hAckQueueMutex = INVALID_HANDLE_VALUE;
	}

	if (state->hSendEvent != NULL)
	{
		CloseHandle (state->hSendEvent);
		state->hSendEvent = INVALID_HANDLE_VALUE;
	}

	if (state->hAckQueueEvent != NULL)
	{
		CloseHandle (state->hAckQueueEvent);
		state->hAckQueueEvent = INVALID_HANDLE_VALUE;
	}

	if (state->hRepeatEvent != NULL)
	{
		CloseHandle (state->hRepeatEvent);
		state->hRepeatEvent = INVALID_HANDLE_VALUE;
	}

	if (state->hLostEvent != NULL)
	{
		CloseHandle (state->hLostEvent);
		state->hLostEvent = INVALID_HANDLE_VALUE;
	}

	if (state->hConnectionEvent != NULL)
	{
		CloseHandle (state->hConnectionEvent);
		state->hConnectionEvent = INVALID_HANDLE_VALUE;
	}

	if (state->hHysterEvent != NULL)
	{
		CloseHandle (state->hHysterEvent);
		state->hHysterEvent = INVALID_HANDLE_VALUE;
	}

	if (state->hDisposeEvent != NULL)
	{
		CloseHandle (state->hDisposeEvent);
		state->hDisposeEvent = INVALID_HANDLE_VALUE;
	}

	if (state->hSenderThread != NULL)
	{
		if (WaitForSingleObject (state->hSenderThread, 5000) == WAIT_TIMEOUT)
			TerminateThread (state->hSenderThread, 0);

		CloseHandle (state->hSenderThread);
		state->hSenderThread = NULL;
	}

#endif
}

void
wxp_state_destroy (p_wxp_state_t state)
{
	/* This is RACY: wait for all threads to leave this state. This need to be fixed NOW */
	wxp_state_clear (state);

	wxp_signal_new_state ();

	if (state->half_packet != NULL)
		free (state->half_packet);

	if (state->queues != NULL)
		wxp_queue_destroy (state->queues);

	free (state);
}


void
wxp_clear_waitkill_states (void)
{
	unsigned int i;

	for (i = 0; i < wxp_state_count; ++i)
		if (wxp_state_list[i] != NULL)
			if (wxp_state_list[i]->wait_kill)
			{
				wxp_add_to_dead_session_history (wxp_state_list[i]->sessid);
				wxp_signal_disposal (wxp_state_list[i]);
				wxp_state_list[i] = NULL;
			}
}

int
wxp_close (p_wxp_state_t state)
{
	char buf[1];

	/* Reset sent. Prevent from wxp_read / wxp_write to lock when reading or writing */
	state->reset_sent = TRUE;

	/* Send RST packet and wait for remote reset */
	wxp_out_queue_reset (state->queues);

	/* This will force to receive all ACKs */
	state->hysteresis_threshold_unlock = 0;
	
	/* Wait for ACK, with a timeout */
	wxp_wait_hysteresis_timeout (state, WXP_DEFAULT_CLOSE_TIMEOUT);

	/* Wait for remote to reset. Add a read timeout or this my hang forever. */
	while (wxp_read (state, buf, 1) != -1);

	wxp_state_set_waitkill (state, WXP_REASON_CONNECTION_RESET);

	wxp_signal_new_state ();

	wxp_wait_disposal (state); /* Wait for state to be removed from the state list */

	/* This is dangerous with lots of threads. PLEASE FIX. */
	wxp_state_destroy (state);

	return 0;
}


int
wxp_state_register (p_wxp_state_t state)
{
	unsigned int i;
	p_wxp_state_t *new_list;

	wxp_global_state_lock ();

	for (i = 0; i < wxp_state_count; ++i)
		if (wxp_state_list[i] == NULL)
			break;

	if (i == wxp_state_count)
	{
		if ((new_list = (p_wxp_state_t *) realloc (wxp_state_list, (wxp_state_count + 1) * sizeof (p_wxp_state_t))) == NULL)
			return -1;

		wxp_state_list = new_list;
		++wxp_state_count;
	}

	wxp_state_list[i] = state;

	wxp_global_state_unlock ();

	return 0;
}

static int
wxp_state_unregister (p_wxp_state_t state)
{
	unsigned int i;
	int result = -1;

	wxp_global_state_lock ();

	for (i = 0; i < wxp_state_count; ++i)
		if (wxp_state_list[i] == state)
		{
			result = 0;
			break;
		}

	wxp_global_state_unlock ();

	return result;
}

p_wxp_state_t
wxp_state_lookup (uint32_t sessid)
{
	unsigned int i;
	p_wxp_state_t result = NULL;

	wxp_global_state_lock ();

	for (i = 0; i < wxp_state_count; ++i)
		if (wxp_state_list[i] != NULL)
			if (wxp_state_list[i]->sessid == sessid && sessid != 0)
			{
				result = wxp_state_list[i];
				break;
			}

	wxp_global_state_unlock ();

	return result;
}

p_wxp_state_t
wxp_state_lookup_by_init_sessid (uint32_t sessid)
{
	unsigned int i;
	p_wxp_state_t result = NULL;

	wxp_global_state_lock ();

	for (i = 0; i < wxp_state_count; ++i)
		if (wxp_state_list[i] != NULL)
			if (wxp_state_list[i]->suggested_sessid == sessid && sessid != 0)
			{
				result = wxp_state_list[i];
				break;
			}

	wxp_global_state_unlock ();

	return result;
}

int
wxp_find_outcoming_packet_by_seq (p_wxp_state_t state, uint16_t seq, p_wxp_pdu_t *pdu, size_t *size)
{
	struct qel *curr;
	p_wxp_pdu_t result = NULL;
	size_t result_size;

	/* TODO: add walk_queue */

	wxp_queue_lock_object (state->queues, WXP_OBJECT_OUTCOMING_QUEUE);

	curr = state->queues->outcoming_q->head;

	while (curr)
	{
		if (ntohs (((p_wxp_pdu_t) curr->data)->seq) == seq)
		{
			result = (p_wxp_pdu_t) curr->data;
			result_size = curr->size;

			break;
		}

		curr = curr->next;
	}

	wxp_queue_unlock_object (state->queues, WXP_OBJECT_OUTCOMING_QUEUE);

	*pdu  = result;
	*size = result_size;

	return result == NULL ? -1 : 0;
}

void
__count_packets_outcoming (void *data, struct qel *qel)
{
	uint32_t *smallest = (uint32_t *) data;
	p_wxp_ack_header_t hdr = (p_wxp_ack_header_t) qel->data;

	if (ntohs (((p_wxp_pdu_t) hdr->data)->seq) < *smallest)
		*smallest = ntohs (((p_wxp_pdu_t) hdr->data)->seq);
}

void
__count_packets_output (void *data, struct qel *qel)
{
	uint32_t *smallest = (uint32_t *) data;

	if (ntohs (((p_wxp_pdu_t) qel->data)->seq) < *smallest)
		*smallest = ntohs (((p_wxp_pdu_t) qel->data)->seq);
}


static int
wxp_state_outcoming_count (p_wxp_state_t state)
{
	int result;
	uint32_t smallest;

	wxp_queue_lock_object (state->queues, WXP_OBJECT_OUTPUT_QUEUE);
	wxp_queue_lock_object (state->queues, WXP_OBJECT_OUTCOMING_QUEUE);

	smallest = state->queues->out_curr_seq;

	packet_queue_walk (state->queues->outcoming_q, __count_packets_outcoming, &smallest);
	packet_queue_walk (state->queues->output_q,    __count_packets_output, &smallest);

	result = state->queues->out_curr_seq - smallest;

	wxp_queue_unlock_object (state->queues, WXP_OBJECT_OUTCOMING_QUEUE);
	wxp_queue_unlock_object (state->queues, WXP_OBJECT_OUTPUT_QUEUE);

	return result;
}

static void
__look_for_confirmed (void *data, struct qel *qel)
{
	uint16_t *seqs = (uint16_t *) data;
	p_wxp_ack_header_t hdr = (p_wxp_ack_header_t) qel->data;
	p_wxp_pdu_t pdu = (p_wxp_pdu_t) hdr->data;

	if (seqs[1])
		if (seqs[0] == ntohs (((p_wxp_pdu_t) hdr->data)->seq))
			seqs[1] = FALSE;
}

BOOL
wxp_seq_already_confirmed (p_wxp_state_t state, uint16_t seq)
{
	uint16_t seqs[2] = {seq, TRUE};

	if (seq >= state->queues->out_curr_seq)
		return FALSE;

	packet_queue_walk (state->queues->outcoming_q, __look_for_confirmed, seqs);

	if (!seqs[1])
		return FALSE;

	return seq < state->highest_ack;
}

int
wxp_remove_from_outcoming (p_wxp_state_t state, const p_wxp_pdu_t pdu, size_t size)
{
	/* Parse packet and remove these ones from outcoming queue, if
	   they tell us to remove a packet twice, it's ok */
	unsigned int entry_count, i;
	int result = 0;
	uint16_t *entries;

	entry_count = (size - sizeof (wxp_pdu_t)) >> 1;
	entries = (uint16_t *) pdu->data;

	for (i = 0; i < entry_count; ++i)
	{
		wxpdbg (WXPDBG_ACK, "Sessid: %08x: state: %p, queues: %p\n", state->sessid, state, state->queues);

		wxp_out_queue_ack_packet (state->queues, ntohs (entries[i]));

		wxpdbg (WXPDBG_ACK, "Sessid: %08x: Packet %d acknowledged (%d elements in queue)\n", state->sessid, ntohs (entries[i]), state->queues->outcoming_q->count);

		if (state->highest_ack < ntohs (entries[i]))
			state->highest_ack = ntohs (entries[i]);

		if (wxp_state_outcoming_count (state) <= state->hysteresis_threshold_unlock)
				wxp_signal_hysteresis (state);
	}

	return result;
}

#if 0
static int
wxp_repeat (p_wxp_state_t state, const p_wxp_pdu_t pdu, size_t size)
{
	/* Do whatever necessary to resend all the packets indicated by PDU */
	unsigned int entry_count, i;
	int result = 0;
	uint16_t *entries;
	p_wxp_pdu_t found_pdu;
	size_t found_pdu_size;

	entry_count = (size - sizeof (wxp_pdu_t)) >> 1;
	entries = (uint16_t *) pdu->data;

	for (i = 0; i < entry_count; ++i)
		if (wxp_find_outcoming_packet_by_seq (state, ntohs (entries[i]), &found_pdu, &found_pdu_size) != -1)
			if ((result = wxp_send_pdu (state, found_pdu, found_pdu_size)) == -1)
				break;

	return result;
}
#endif

/* Actual API functions */
p_wxp_state_t
wxp_connect (wxp_addr_t source)
{
	p_wxp_state_t state;
	static uint32_t sessid;
	int n;

	if ((state = wxp_state_new ()) == NULL)
		return NULL;

	state->sessid = wxp_random ();
	state->src    = source;

	if (wxp_state_register (state) == -1)
	{
		wxp_state_destroy (state);
		return NULL;
	}

	wxpdbg (WXPDBG_SESS, "WXP Connect: suggesting state with sessid: %p\n", state->sessid);

	n = 0;

	do
	{
		if (state->connected)
			break;

		wxpdbg (WXPDBG_SESS, "Sending SYN %d/%d...\n", n + 1, WXP_MAX_CONN_RETRY);
		wxp_send_syn (source, current_remote_address, state->sessid);
	}
	while (wxp_wait_connection_completion (state) == -1 && ++n < WXP_MAX_CONN_RETRY);

	if (!state->connected)
	{
		wxp_state_set_waitkill (state, WXP_REASON_CONNECTION_TIMEOUT);
		wxp_signal_new_state ();
		wxp_close (state);

		return NULL;
	}

	return state;
}

p_wxp_state_t
wxp_listen (wxp_addr_t source)
{
	p_wxp_state_t state;

	while ((state = wxp_pull_listening_state ()) == NULL)
		wxp_wait_new_connection ();

	return state;
}

int
wxp_read (p_wxp_state_t state, void *data, size_t size)
{
	void *input;
	size_t input_size;
	size_t p = 0;

	if (state == NULL)
		return -1;

	if (state->half_packet != NULL)
	{
		input_size = size < state->half_packet_size ? size : state->half_packet_size;

		memcpy (data, state->half_packet, input_size);

		state->half_packet_size -= input_size;
		size -= input_size;
		p    += input_size;

		if (state->half_packet_size > 0)
			memmove (state->half_packet, state->half_packet + input_size, state->half_packet_size);
		else
		{
			free (state->half_packet);
			state->half_packet = NULL;
		}

		return input_size;
	}

	while (packet_queue_pick_lock (state->queues, state->queues->input_q, WXP_OBJECT_INPUT_QUEUE, &input, &input_size) == -1)
	{
		if (!state->connected || state->wait_kill || state->reset_sent)
			return -1;

		wxp_wait_for_object (state->queues, WXP_OBJECT_INPUT_QUEUE, 3000);
	}

	if (input_size > size)
	{
		state->half_packet_size = input_size - size;

		if ((state->half_packet = (uint8_t *) malloc (state->half_packet_size)) == NULL)
		{
			free (input);
			return -1;
		}

		memcpy (state->half_packet, (char *) input + size, state->half_packet_size);

		input_size = size;
	}

	memcpy ((char *) data + p, input, input_size);

	free (input);

	return input_size + p;
}

int
wxp_write (p_wxp_state_t state, const void *data, size_t size)
{
	if (state == NULL)
		return -1;

	if (!state->connected || state->wait_kill || state->reset_sent)
	{
		wxpdbg (WXPDBG_API, "wxp_write failed on closed session %p\n", state->sessid);
		return -1;
	}

	if (size > (current_backend->get_mtu) (current_backend_data))
		size = (current_backend->get_mtu) (current_backend_data);

	wxpdbg (WXPDBG_API, "wxp_write(%p)\n", state->sessid);

	if (wxp_state_outcoming_count (state) >= state->hysteresis_threshold_lock)
		while (wxp_state_outcoming_count (state) > state->hysteresis_threshold_unlock)
			wxp_wait_hysteresis (state);

	wxpdbg (WXPDBG_API, "wxp_write on session %p: %d bytes, %d packets in outcoming, out curr seq: %d\n", state->sessid, size, wxp_state_outcoming_count (state), state->queues->out_curr_seq);

	if (wxp_out_queue_write (state->queues, data, size) == -1)
	{
		wxpdbg (WXPDBG_QUEUES, "OUTPUT QUEUE ERROR!\n");
		return -1;
	}

	wxp_sched_send (state);

	return size;
}
