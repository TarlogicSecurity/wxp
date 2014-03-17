/* 
 * wxp_queue.c: WXP queue set (incoming, outcoming, input and output)
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

p_wxp_queue_t
wxp_queue_new (void)
{
	p_wxp_queue_t queue;

	if ((queue = (p_wxp_queue_t) calloc (1, sizeof (wxp_queue_t))) == NULL)
		goto FAIL_MISERABLY;

	if ((queue->output_q = packet_queue_new ()) == NULL)
		goto FAIL_MISERABLY;

	if ((queue->outcoming_q = packet_queue_new ()) == NULL)
		goto FAIL_MISERABLY;

	if ((queue->input_q = packet_queue_new ()) == NULL)
		goto FAIL_MISERABLY;

	if ((queue->incoming_q = packet_queue_new ()) == NULL)
		goto FAIL_MISERABLY;

#ifdef _WIN32
	if ((queue->hOutputQueueChangeEvent = CreateEvent (NULL, FALSE, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((queue->hInputQueueChangeEvent = CreateEvent (NULL, FALSE, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((queue->hOutputQueueReadyEvent = CreateEvent (NULL, FALSE, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((queue->hInputQueueReadyEvent = CreateEvent (NULL, FALSE, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((queue->hOutputQueueMutex = CreateMutex (NULL, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((queue->hInputQueueMutex = CreateMutex (NULL, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((queue->hOutcomingQueueMutex = CreateMutex (NULL, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;

	if ((queue->hIncomingQueueMutex = CreateMutex (NULL, FALSE, NULL)) == NULL)
		goto FAIL_MISERABLY;
#endif

	return queue;

FAIL_MISERABLY:
	if (queue != NULL)
		wxp_queue_destroy (queue);

	return NULL;
}

void
ReleaseMutexAndClose (PHANDLE pH)
{
	HANDLE tmp;

	tmp = *pH;

	*pH = NULL;

	ReleaseMutex (tmp);

	CloseHandle (tmp);
}

void
SetEventAndClose (PHANDLE pH)
{
	HANDLE tmp;

	tmp = *pH;

	*pH = NULL;

	SetEvent (tmp);

	CloseHandle (tmp);
}

void
wxp_queue_destroy_mutexes (p_wxp_queue_t queue)
{
	queue->dead = TRUE;

#ifdef _WIN32
	if (queue->hIncomingQueueMutex != NULL)
		ReleaseMutexAndClose (&queue->hIncomingQueueMutex);

	if (queue->hOutcomingQueueMutex != NULL)
		ReleaseMutexAndClose (&queue->hOutcomingQueueMutex);

	if (queue->hInputQueueMutex != NULL)
		ReleaseMutexAndClose (&queue->hInputQueueMutex);

	if (queue->hOutputQueueMutex != NULL)
		ReleaseMutexAndClose (&queue->hOutputQueueMutex);

	if (queue->hInputQueueReadyEvent != NULL)
		SetEventAndClose (&queue->hInputQueueReadyEvent);

	if (queue->hInputQueueChangeEvent != NULL)
		SetEventAndClose (&queue->hInputQueueChangeEvent);

	if (queue->hOutputQueueReadyEvent != NULL)
		SetEventAndClose (&queue->hOutputQueueReadyEvent);

	if (queue->hOutputQueueChangeEvent != NULL)
		SetEventAndClose (&queue->hOutputQueueChangeEvent);
#endif
}

void
wxp_queue_destroy (p_wxp_queue_t queue)
{
	struct packet_queue *tmp;

	wxp_queue_destroy_mutexes (queue);

	if (queue->incoming_q != NULL)
	{
		tmp = queue->incoming_q;
		queue->incoming_q = NULL;
		packet_queue_destroy (tmp);
	}

	if (queue->input_q != NULL)
	{
		tmp = queue->input_q;
		queue->input_q = NULL;
		packet_queue_destroy (tmp);
	}

	if (queue->outcoming_q != NULL)
	{
		tmp = queue->outcoming_q;
		queue->outcoming_q = NULL;
		packet_queue_destroy (tmp);
	}

	if (queue->output_q != NULL)
	{
		tmp = queue->output_q;
		queue->output_q = NULL;
		packet_queue_destroy (tmp);
	}

	free (queue);
}

void
wxp_queue_lock_object (p_wxp_queue_t queue, wxp_queue_object_type_t obj)
{
#ifdef _WIN32
	HANDLE mutexHandles[] = {queue->hInputQueueMutex, queue->hOutputQueueMutex, queue->hIncomingQueueMutex, queue->hOutcomingQueueMutex};
#endif
	if (obj < 0 || obj >= 4)
		return;

#ifdef _WIN32
	WaitForSingleObject (mutexHandles[obj], INFINITE);
#endif
}

void
wxp_queue_unlock_object (p_wxp_queue_t queue, wxp_queue_object_type_t obj)
{
#ifdef _WIN32
	HANDLE mutexHandles[] = {queue->hInputQueueMutex, queue->hOutputQueueMutex, queue->hIncomingQueueMutex, queue->hOutcomingQueueMutex};
#endif
	if (obj < 0 || obj >= 4)
		return;

#ifdef _WIN32
	ReleaseMutex (mutexHandles[obj]);
#endif
}

void
wxp_wait_for_object (p_wxp_queue_t queue, wxp_queue_object_type_t obj, uint32_t timeout)
{
#ifdef _WIN32
	HANDLE mutexHandles[] = {queue->hInputQueueReadyEvent, queue->hOutputQueueReadyEvent, queue->hInputQueueChangeEvent, queue->hOutputQueueChangeEvent};
#endif
	if (obj < 0 || obj >= 4)
		return;

#ifdef _WIN32
	if (timeout == 0)
		timeout = INFINITE;

	WaitForSingleObject (mutexHandles[obj], timeout);
#endif
}

void
wxp_signal_object (p_wxp_queue_t queue, wxp_queue_object_type_t obj)
{
#ifdef _WIN32
	HANDLE mutexHandles[] = {queue->hInputQueueReadyEvent, queue->hOutputQueueReadyEvent, queue->hInputQueueChangeEvent, queue->hOutputQueueChangeEvent};
#endif
	if (obj < 0 || obj >= 4)
		return;

#ifdef _WIN32
	SetEvent (mutexHandles[obj]);
#endif
}

int
wxp_out_queue_write (p_wxp_queue_t queue, const void *data, size_t size)
{
	p_wxp_pdu_t pdu;
	size_t pdu_size;
	int result;

	pdu_size = sizeof (wxp_pdu_t) + size;

	if ((pdu = (p_wxp_pdu_t) calloc (1, pdu_size)) == NULL)
		return -1;

	wxp_queue_lock_object (queue, WXP_OBJECT_OUTPUT_QUEUE);

	/* Checksum is calculated at send time */
	pdu->type = htons (WXP_TYPE_DATA);
	pdu->seq  = htons (queue->out_curr_seq);

	memcpy (pdu->data, data, size);

	if ((result = packet_queue_put (queue->output_q, pdu, pdu_size)) != -1)
		queue->out_curr_seq++;

	wxp_queue_unlock_object (queue, WXP_OBJECT_OUTPUT_QUEUE);

	wxp_signal_object (queue, WXP_OBJECT_OUTPUT_QUEUE);

	free (pdu);

	return result;
}

int
wxp_out_queue_reset (p_wxp_queue_t queue)
{
	p_wxp_pdu_t pdu;
	size_t pdu_size;
	int result;

	pdu_size = sizeof (wxp_pdu_t);

	if ((pdu = (p_wxp_pdu_t) calloc (1, pdu_size)) == NULL)
		return -1;

	wxp_queue_lock_object (queue, WXP_OBJECT_OUTPUT_QUEUE);

	/* Checksum is calculated at send time */
	pdu->type = htons (WXP_TYPE_RST);
	pdu->seq  = htons (queue->out_curr_seq);

	if ((result = packet_queue_put (queue->output_q, pdu, pdu_size)) != -1)
		queue->out_curr_seq++;

	wxp_queue_unlock_object (queue, WXP_OBJECT_OUTPUT_QUEUE);

	wxp_signal_object (queue, WXP_OBJECT_OUTPUT_QUEUE);

	free (pdu);

	return result;
}

uint64_t
wxp_get_timestamp (void)
{
#ifdef _WIN32
	return GetTickCount64 ();
#endif
}

static int
packet_queue_put_lock (p_wxp_queue_t queue, struct packet_queue *q, wxp_queue_object_type_t obj, void *pdu, size_t size)
{
	int result;

	wxp_queue_lock_object (queue, obj);

	result = packet_queue_put (q, pdu, size);

	wxp_queue_unlock_object (queue, obj);

	return result;
}

int
packet_queue_pick_lock (p_wxp_queue_t queue, struct packet_queue *q, wxp_queue_object_type_t obj, void **pdu, size_t *size)
{
	int result;

	wxp_queue_lock_object (queue, obj);

	result = packet_queue_pick (q, (void **) pdu, size);

	wxp_queue_unlock_object (queue, obj);

	return result;
}

static int
packet_queue_peek_lock (p_wxp_queue_t queue, struct packet_queue *q, wxp_queue_object_type_t obj, void **pdu, size_t *size)
{
	int result;

	wxp_queue_lock_object (queue, obj);

	result = packet_queue_peek (q, (void **) pdu, size);

	wxp_queue_unlock_object (queue, obj);

	return result;
}

/* Must be not locking as it's called when an event is received */
int
wxp_out_queue_pick (p_wxp_queue_t queue, p_wxp_pdu_t *pdu, size_t *size)
{
	p_wxp_pdu_t this_pdu;
	p_wxp_ack_header_t pending_pdu;

	size_t this_size;
	size_t pending_pdu_size;

	while (packet_queue_pick_lock (queue, queue->output_q, WXP_OBJECT_OUTPUT_QUEUE, (void **) &this_pdu, &this_size) == -1)
		return -1;

	wxp_signal_object (queue, WXP_OBJECT_OUTPUT_QUEUE);

	pending_pdu_size = sizeof (wxp_ack_header_t) + this_size;

	if ((pending_pdu = (p_wxp_ack_header_t) calloc (1, pending_pdu_size)) == NULL)
	{
		*pdu = NULL;
		*size = 0;
		return -1;
	}

	pending_pdu->timestamp = wxp_get_timestamp ();
	pending_pdu->retry_count = 0;
	
	memcpy (pending_pdu->data, this_pdu, this_size);

	if (packet_queue_put_lock (queue, queue->outcoming_q, WXP_OBJECT_OUTCOMING_QUEUE, pending_pdu, pending_pdu_size) == -1)
	{
		free (pending_pdu);
		*pdu = NULL;
		*size = 0;
		return -1;
	}

	free (pending_pdu);
	
	*pdu  = this_pdu;
	*size = this_size;

	wxp_signal_object (queue, WXP_OBJECT_OUTCOMING_QUEUE);

	return 0;
}

/* This function stinks */
int
wxp_out_queue_ack_packet (p_wxp_queue_t queue, uint16_t seq)
{
	int result = -1;
	struct qel *curr;
	p_wxp_pdu_t pdu;

	wxp_queue_lock_object (queue, WXP_OBJECT_OUTCOMING_QUEUE);

	curr = queue->outcoming_q->head;

	/* TODO: write walk_queue */
	while (curr)
	{
		pdu = (p_wxp_pdu_t) ((p_wxp_ack_header_t) curr->data)->data;

		if (ntohs (pdu->seq) == seq)
			break;

		curr = curr->next;
	}


	if (curr != NULL)
	{
		wxpdbg (WXPDBG_ACK, "| found packet! seq=%d. Before: %d\n", seq, queue->outcoming_q->count);

		packet_queue_remove (queue->outcoming_q, curr);

		wxpdbg (WXPDBG_ACK, "\\__ After: %d\n", queue->outcoming_q->count);

		result = 0;
	}

	wxp_queue_unlock_object (queue, WXP_OBJECT_OUTCOMING_QUEUE);

	return result;
}


uint64_t
wxp_out_get_min_timeout (p_wxp_queue_t queue)
{
	struct qel *curr;
	p_wxp_ack_header_t header;
	uint64_t curr_timeout = 0xffffffffffffffffull; /* mmmmmmmmmmmmmmmmmetal jjjjjjjjjjjjjacket */
	uint64_t curr_timestamp = wxp_get_timestamp ();

	wxp_queue_lock_object (queue, WXP_OBJECT_OUTCOMING_QUEUE);

	curr = queue->outcoming_q->tail;

	while (curr)
	{
		header = (p_wxp_ack_header_t) curr->data;

		if (WXP_DEFAULT_REPEAT_TIMEOUT - (curr_timestamp - header->timestamp) < curr_timeout)
			curr_timeout = WXP_DEFAULT_REPEAT_TIMEOUT - (curr_timestamp - header->timestamp);

		curr = curr->prev;
	}

	wxp_queue_unlock_object (queue, WXP_OBJECT_OUTCOMING_QUEUE);

	return curr_timeout;
}

static void
wxp_debug_cb (void *data, struct qel *qel)
{
	p_wxp_pdu_t hdr = (p_wxp_pdu_t) qel->data;
}


/* This function excepts queue to be locked */
static BOOL
wxp_incoming_already_received (p_wxp_queue_t queue, uint16_t seq)
{
	struct qel *curr;
	p_wxp_pdu_t pdu;

	curr = queue->incoming_q->head;

	while (curr)
	{
		pdu = (p_wxp_pdu_t) curr->data;
		
		if (ntohs (pdu->seq) == seq)
			return TRUE;

		curr = curr->next;
	}

	return FALSE;
}

struct packet_info
{
	p_wxp_pdu_t pdu_data;
	size_t      pdu_size;
};

struct packet_array
{
	int                 packet_count;
	struct packet_info *packet_list;
};

static void
wxp_fill_seq_cb (void *data, struct qel *qel)
{
	struct array_header *hdr = (struct array_header *) data;

	hdr->seq[hdr->count++] = ntohs (((p_wxp_pdu_t) qel->data)->seq);
}

static int
__compare_packet_info (const void *a, const void *b)
{
	return ntohs (((struct packet_info *) a)->pdu_data->seq) - ntohs (((struct packet_info *) b)->pdu_data->seq);
}

/* Again, this function needs the incoming queue to be locked */
static int
wxp_incoming_queue_sort (p_wxp_queue_t queue)
{
	struct packet_array array;
	int i;

	array.packet_count = 0;

	if (packet_queue_is_empty (queue->incoming_q))
		return 0;

	/* TODO: add something like get_queue_size */
	if ((array.packet_list = (struct packet_info *) calloc (queue->incoming_q->count, sizeof (struct packet_info))) == NULL)
		return -1;

	/* Move all packets to the list */
	while (packet_queue_pick (queue->incoming_q, (void **) &array.packet_list[array.packet_count].pdu_data, &array.packet_list[array.packet_count].pdu_size) != -1)
		++array.packet_count;

	assert (queue->incoming_q->count == 0);

	/* Sort them */
	qsort (array.packet_list, array.packet_count, sizeof (struct packet_info), __compare_packet_info);

	/* Put them back again */
	for (i = 0; i < array.packet_count; ++i)
		if (packet_queue_put (queue->incoming_q, array.packet_list[i].pdu_data, array.packet_list[i].pdu_size) == -1)
		{
			while (i < array.packet_count)
				free (array.packet_list[i++].pdu_data); /* Cleanup before failing properly */

			free (array.packet_list);

			return -1;
		}
		else
			free (array.packet_list[i].pdu_data); /* Not needed anymore, already in queue */

	assert (queue->incoming_q->count == array.packet_count);

	/* Now, our queue is sorted. We can get rid of the packet array */
	free (array.packet_list);

	return 0;
}

int
wxp_in_put (p_wxp_queue_t queue, p_wxp_pdu_t pdu, size_t size)
{
	int result;
	BOOL mustclose = FALSE;
	BOOL input_data = FALSE;

	p_wxp_pdu_t pending_pdu;
	size_t pending_size;

	wxp_queue_lock_object (queue, WXP_OBJECT_INPUT_QUEUE);
	wxp_queue_lock_object (queue, WXP_OBJECT_INCOMING_QUEUE);

	if (ntohs (pdu->seq) == queue->in_curr_seq)
	{
		if (ntohs (pdu->type) == WXP_TYPE_RST)
			mustclose = TRUE;
		else
		{
			/* Zero-length packets are only useful for connection testing purposes */
			if ((size - sizeof (wxp_pdu_t)) > 0)
			{
				if (packet_queue_put (queue->input_q, pdu->data, size - sizeof (wxp_pdu_t)) == -1)
				{
					wxp_queue_unlock_object (queue, WXP_OBJECT_INCOMING_QUEUE);
					wxp_queue_unlock_object (queue, WXP_OBJECT_INPUT_QUEUE);

					return -1;
				}

				input_data = TRUE;
			}
		}

		++queue->in_curr_seq;

		packet_queue_walk (queue->incoming_q, wxp_debug_cb, queue);

		/* Try to see if we have incoming packets over here */
		while (packet_queue_peek (queue->incoming_q, (void **) &pending_pdu, &pending_size) != -1)
		{
			if (ntohs (pending_pdu->seq) == queue->in_curr_seq)
			{
				/* It will forcefully work as we're the only thread using this queue and packet_queue_peek
				   worked right before this call */
				(void) packet_queue_pick (queue->incoming_q, (void **) &pending_pdu, &pending_size);

				if (ntohs (pending_pdu->type) == WXP_TYPE_RST)
					mustclose = TRUE;

				if (!mustclose && (pending_size - sizeof (wxp_pdu_t)) > 0)
				{
					if (packet_queue_put (queue->input_q, pending_pdu->data, pending_size - sizeof (wxp_pdu_t)) == -1)
					{
						wxp_queue_unlock_object (queue, WXP_OBJECT_INCOMING_QUEUE);
						wxp_queue_unlock_object (queue, WXP_OBJECT_INPUT_QUEUE);

						return -1;
					}

					input_data = TRUE;
				}

				free (pending_pdu);

				wxp_signal_object (queue, WXP_OBJECT_INCOMING_QUEUE);

				++queue->in_curr_seq;
			}
			else
				break;
		}
		
		if (input_data)
			wxp_signal_object (queue, WXP_OBJECT_INPUT_QUEUE);

		result = mustclose ? WXP_INCOMING_STATE_CLOSE : (input_data ? WXP_INCOMING_STATE_ZERO_PACKET : WXP_INCOMING_STATE_EXPECTED);
	}
	else if (ntohs (pdu->seq) > queue->in_curr_seq) /* Lost packet! put it in queue */
	{
		/* Check if we received it already, if it's not */
		if (!wxp_incoming_already_received (queue, ntohs (pdu->seq)))
		{
			/* This queue holds fully-formed PDUs */
			if (packet_queue_put (queue->incoming_q, pdu, size) == -1)
				return -1;

			/* Sort sequence numbers */
			wxp_incoming_queue_sort (queue);

			wxp_signal_object (queue, WXP_OBJECT_INCOMING_QUEUE); /* TODO: put this signals in packet_queue_xxx_lock */

			result = WXP_INCOMING_STATE_LOST_PACKET;

			assert (queue->incoming_q->count > 0);
		}
		else
			result = WXP_INCOMING_STATE_REPEATED;
	}
	else
		result = WXP_INCOMING_STATE_REPEATED;

	wxp_queue_unlock_object (queue, WXP_OBJECT_INCOMING_QUEUE);
	wxp_queue_unlock_object (queue, WXP_OBJECT_INPUT_QUEUE);
	
	return result;
}

BOOL
wxp_in_queue_empty (p_wxp_queue_t queue)
{
	void *ign_data;
	size_t ign_size;

	return packet_queue_peek_lock (queue, queue->input_q, WXP_OBJECT_INPUT_QUEUE, &ign_data, &ign_size) == -1;
}

int
wxp_in_queue_read (p_wxp_queue_t queue, void **data, size_t *size)
{
	while (packet_queue_pick_lock (queue, queue->input_q, WXP_OBJECT_INPUT_QUEUE, data, size) == -1 && !queue->dead)
		wxp_wait_for_object (queue, WXP_OBJECT_INPUT_QUEUE, WXP_WAIT_FOREVER);

	if (queue->dead)
		return -1;

	return 0;
}


