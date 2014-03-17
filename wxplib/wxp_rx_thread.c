/* 
 * wxp_rx_thread.c: common RX thread: packet validation and decoding.
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

#include <time.h>
#include <stdio.h>

uint32_t      dead_session_history[32];
unsigned int  dead_session_ptr;

int
wxp_add_to_dead_session_history (uint32_t sessid)
{
	dead_session_history[dead_session_ptr++ % WXP_DEAD_HISTORY_SIZE] = sessid;

	return 0;
}

static BOOL
wxp_recently_dead (uint32_t sessid)
{
	unsigned int i;

	for (i = 0; i < (dead_session_ptr > WXP_DEAD_HISTORY_SIZE ? WXP_DEAD_HISTORY_SIZE : dead_session_ptr); ++i)
		if (dead_session_history[i] == sessid)
			return TRUE;

	return FALSE;
}

int
wxp_receiver_thread (void)
{
	int ev_src;
	int result;

	p_wxp_pdu_t   incoming_pdu;
	p_wxp_state_t state;

	size_t      incoming_size;
	wxp_addr_t  incoming_src_addr;
	wxp_addr_t  incoming_dst_addr;
	uint32_t    expected_checksum;

	const p_wxp_backend_t current_backend = wxp_get_current_backend ();
	void *current_backend_data = wxp_get_current_backend_data ();
	wxp_addr_t current_remote_address = wxp_get_current_remote_address ();

	char *pktypes[] = {"NULL  ", "DATA  ", "ACK   ", "RST   ", "REPEAT", "SYN   ", "SYNACK"};

	while ((ev_src = wxp_wait_for_event ()) != -1)
	{
		if (ev_src == WXP_EVENT_NEW_DATA) /* Time to read stuff */
		{
			/* Is up to the backend to determine whether the packet is sent to us */
			if ((result = (current_backend->recvfrom) (current_backend_data, &incoming_src_addr, &incoming_dst_addr, (void **) &incoming_pdu, &incoming_size)) == 0)
			{
				/* FIX this: we need to add somethink like "check_remote_address" in order
				   to determine the trustness of the remote host */
				if (wxp_addrcmp (&incoming_src_addr, &current_remote_address) == 0 && incoming_size >= sizeof (wxp_pdu_t))
				{
					/* This packet is definitely from remote host */
					expected_checksum = ntohl (incoming_pdu->checksum);
					incoming_pdu->checksum = htonl (0);

					/* If the packet is okay... */
					if (wxp_calc_checksum (incoming_pdu, incoming_size) == expected_checksum)
					{
						wxpdbg (WXPDBG_RECV, "[%s] sessid=%08x, seq/count/new_sessid=%08x, size=%d\n", pktypes[ntohs (incoming_pdu->type)], ntohl (incoming_pdu->sessid), ntohl (incoming_pdu->new_sessid), incoming_size); 

						/* If it corresponds to an existing session... */
						/* WARNING: even if it's impossible to destroy a state from two
						   different threads, serialize this block for the sake of coherency */
						if ((state = wxp_state_lookup (ntohl (incoming_pdu->sessid))) != NULL)
						{
							if (!state->connected && ntohs (incoming_pdu->type) == WXP_TYPE_DATA) /* Early connection! The confirmation ACK was lost. This is also valid for a connection. */
							{
								state->connected = TRUE;

								wxp_signal_new_connection (); /* Ready for a listener to get it */

								wxpdbg (WXPDBG_SESS, "Server-side: Connection finished (with DATA, instead of ACK) sessid: %08x\n", state->sessid);
							}

							if (!state->connected)
							{
								if (ntohs (incoming_pdu->type) == WXP_TYPE_ACK) /* Only happens in server mode */
								{
									state->connected = TRUE;

									wxp_signal_new_connection (); /* Ready for a listener to get it */

									wxpdbg (WXPDBG_SESS, "Server-side: Connection finished, sessid: %08x\n", state->sessid);
								}
								else if (ntohs (incoming_pdu->type) == WXP_TYPE_SYNACK) /* Only happens in client mode */
								{
									state->connected = TRUE;

									state->suggested_sessid = state->sessid;

									state->sessid = ntohl (incoming_pdu->new_sessid);

									/* Send ACK */
									result = wxp_send_ack (incoming_dst_addr, incoming_src_addr, state->sessid);

									wxpdbg (WXPDBG_SESS, "Client-side: Synack received, new sessid is %p\n", state->sessid);

									wxp_signal_connection_completion (state);
								}
								else if (ntohs (incoming_pdu->type) == WXP_TYPE_RST)
								{
									/* Connection failed unexpectedly */
									wxp_state_set_waitkill (state, WXP_REASON_CONNECTION_RESET);

									wxp_signal_connection_completion (state); /* Signal both */
								}
								else /* Send RST. */
									result = wxp_send_rst (incoming_dst_addr, incoming_src_addr, ntohl (incoming_pdu->sessid), -1);
							}
							else
								switch (ntohs (incoming_pdu->type))
								{
								case WXP_TYPE_RST: /* Peer wants to close the connection. RST messages must be ordered too. */
								case WXP_TYPE_DATA: /* Data packet must be sent to the queues and ack'ed */
									if ((result = wxp_in_put (state->queues, incoming_pdu, incoming_size)) != -1)
									{
										if (result == WXP_INCOMING_STATE_LOST_PACKET)
											wxp_sched_lost (state);
										else if (result == WXP_INCOMING_STATE_CLOSE)
										{
											if (!state->reset_sent)
											{
												/* This sould be improved discarding all outcoming packets and sending
												it as soon as possible */
												wxp_out_queue_reset (state->queues);

												state->reset_sent = TRUE; /* wxp_read won't wait any longer */

												wxpdbg (WXPDBG_SESS, "There was a RST message pending, RST message queued!\n");
											}
										}
											
										wxpdbg (WXPDBG_QUEUES, "Queues %08x (incoming_seq: %d)\n", state->sessid, state->queues->in_curr_seq);
										wxpdbg (WXPDBG_QUEUES, "Queue state: %d (received: %d)\n", result, ntohs (incoming_pdu->seq));
										wxpdbg (WXPDBG_QUEUES, "   Input queue size: %d\n", state->queues->input_q->count);
										wxpdbg (WXPDBG_QUEUES, "   Output queue size: %d\n", state->queues->output_q->count);
										wxpdbg (WXPDBG_QUEUES, "   Incoming queue size: %d\n", state->queues->incoming_q->count);
										wxpdbg (WXPDBG_QUEUES, "   Outcoming queue size: %d\n", state->queues->outcoming_q->count);

										result = wxp_sched_ack (state, incoming_pdu);
									}
									break;

								case WXP_TYPE_ACK: /* Ack tells us that it's time to remove packets from outcoming queues */
									result = wxp_remove_from_outcoming (state, incoming_pdu, incoming_size);
									wxp_sched_repeat_periodically (state);
									break;

								case WXP_TYPE_REPEAT: /* Repeat what we have in the outcoming queues, if we don't have it, no prob */
									wxpdbg (WXPDBG_REP, "Repeat message received!\n");
									wxp_sched_repeat (state);
									break;
								}
						}
						else
						{
							/* Let's make some room for the incoming connection, if we can */
							wxp_cleanup_expired_listening_states ();

							if (ntohs (incoming_pdu->type) == WXP_TYPE_SYN)
							{
								if ((state = wxp_get_listening_state_by_suggested_sessid (ntohl (incoming_pdu->sessid))) != NULL)
									result = wxp_send_synack (incoming_dst_addr, incoming_src_addr, state->suggested_sessid, state->sessid);
								else if ((state = wxp_state_new ()) != NULL)
								{
									state->sessid = wxp_random ();
									state->src    = incoming_src_addr;
									state->dst    = incoming_dst_addr;
									state->server = TRUE;
									state->first_syn_timestamp = wxp_get_timestamp ();

									state->suggested_sessid = ntohl (incoming_pdu->sessid);

									if (wxp_state_register (state) == -1)
									{
										wxpdbg (WXPDBG_SESS, "No memory, refusing to allocate...\n");

										wxp_state_destroy (state);

										result = wxp_send_rst (incoming_dst_addr, incoming_src_addr, ntohl (incoming_pdu->sessid), -1);
									}
									else if (wxp_push_listening_state (state) == -1)
									{
										wxpdbg (WXPDBG_SESS, "Too many incoming connections, refusing to allocate...\n");

										wxp_state_set_waitkill (state, WXP_REASON_TOO_MANY_CONNECTIONS);

										wxp_clear_waitkill_states ();

										wxp_state_destroy (state);
										
										result = wxp_send_rst (incoming_dst_addr, incoming_src_addr, ntohl (incoming_pdu->sessid), -1);
									}
									else
									{
										wxpdbg (WXPDBG_SESS, "New connection request, listening to sessid: %08x\n", state->sessid);

										result = wxp_send_synack (incoming_dst_addr, incoming_src_addr, state->suggested_sessid, state->sessid);
										
										wxp_sched_repeat_periodically (state);
									}
								}
								else
									result = wxp_send_rst (incoming_dst_addr, incoming_src_addr, ntohl (incoming_pdu->sessid), -1);
							}
							else if (ntohs (incoming_pdu->type) == WXP_TYPE_SYNACK) /* No session with this ID, probably because we're connected already */
							{
								/* Let's look for old sessids */
								if ((state = wxp_state_lookup_by_init_sessid (ntohl (incoming_pdu->sessid))) == NULL)
								{
									result = wxp_send_ack (incoming_dst_addr, incoming_src_addr, ntohl (incoming_pdu->new_sessid)); /* Remind the remote peer we're ok */
									wxpdbg (WXPDBG_SESS, "Synack when already connected! Repeating %p\n", ntohl (incoming_pdu->sessid));
								}
								else
									wxpdbg (WXPDBG_SESS, "Synack when already connected! Couldn't find recently acked session %p\n", ntohl (incoming_pdu->sessid));
							}
							else
								wxpdbg (WXPDBG_SESS, "Received PDU (sessid %p) is in nonregistered session\n", ntohl (incoming_pdu->sessid));
						}
					}
					else
						wxpdbg (WXPDBG_RECV, "[XXXXXX] Broken packet of %d bytes\n", incoming_size);
				}

				free (incoming_pdu); /* Don't need this anymore */
			}
			else
				result = 0; /* No packets? no prob */

			/* Not an else: something may go terribly wrong even if we parse something right */
			if (result == -1)
				break; 
		}
		else if (ev_src == WXP_EVENT_NEW_STATE) /* States are being closed */
		{
			wxp_global_state_lock ();

			wxp_clear_waitkill_states ();

			wxp_global_state_unlock ();
		}

	}

	return -1;
}
