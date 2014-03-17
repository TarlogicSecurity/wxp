/* 
 * wxp_state.h: prototypes and definition for the main WXP API.
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

#ifndef _WXP_WXP_STATE_H
#define _WXP_WXP_STATE_H

#ifdef _WIN32
#include <Windows.h>
#else
#error Non-Windows platforms currently unsupported
#endif

#include <stdint.h>
#include <assert.h>

#include "queue.h"

#ifdef __cplusplus
extern "C"
{
#endif

// #define WXP_TEST

#define WXPDBG_QUEUES  0
#define WXPDBG_RECV    1
#define WXPDBG_SEND    2
#define WXPDBG_ACK     3
#define WXPDBG_REP     4
#define WXPDBG_SESS    5
#define WXPDBG_EVENT   6
#define WXPDBG_API     7

#define WXP_DEAD_HISTORY_SIZE 32

#define WXP_DEFINE_LISTEN_QUEUE_SIZE 16
#define WXP_DEFAULT_LOCK_THRESHOLD   10
#define WXP_DEFAULT_UNLOCK_THRESHOLD 5

#define WXP_DEFAULT_CLOSE_TIMEOUT  30000
#define WXP_DEFAULT_REPEAT_TIMEOUT 5000
#define WXP_DEFAULT_CONN_TIMEOUT   5000
#define WXP_DEFAULT_SYNACK_TIMEOUT 30000
#define WXP_REPEAT_CHECK_PERIOD    2000
#define WXP_SEND_CHECK_PERIOD      1000
#define WXP_MAX_RETRY              50
#define WXP_MAX_CONN_RETRY         5
#define WXP_ACK_QUEUE_SLEEP        100   /* How much to wait until sending an ack */
#define WXP_OUT_QUEUE_SLEEP        0     /* This is necessary if we want to pack several packets in one */
#define WXP_REP_QUEUE_SLEEP        10    /* How much to wait when somebody ask to repeat */
#define WXP_LOST_QUEUE_SLEEP       5000  /* How much to wait when we find lost packets */


#define WXP_WAIT_FOREVER           0

#define WXP_TYPE_DATA    1
#define WXP_TYPE_ACK     2
#define WXP_TYPE_RST     3
#define WXP_TYPE_REPEAT  4
#define WXP_TYPE_SYN     5
#define WXP_TYPE_SYNACK  6

#define WXP_ACK_PDU_MAX_ENTRIES        100
#define WXP_REP_PDU_MAX_ENTRIES        100

#define WXP_INCOMING_STATE_EXPECTED    0
#define WXP_INCOMING_STATE_LOST_PACKET 1
#define WXP_INCOMING_STATE_REPEATED    2
#define WXP_INCOMING_STATE_CLOSE       3
#define WXP_INCOMING_STATE_ZERO_PACKET 4

#define WXP_EVENT_NEW_DATA             0
#define WXP_EVENT_NEW_STATE            1
#define WXP_EVENT_SEND                 2

#define WXP_SENDER_EVENT_ACK           0
#define WXP_SENDER_EVENT_REPEAT        1
#define WXP_SENDER_EVENT_LOST          2
#define WXP_SENDER_EVENT_SEND          3

struct array_header
{
	uint16_t count;
	uint16_t *seq;
};

typedef enum wxp_close_reason
{
	WXP_REASON_CONNECTION_RESET,
	WXP_REASON_CONNECTION_TIMEOUT,
	WXP_REASON_ACK_TIMEOUT,
	WXP_REASON_STATE_CLEARED,
	WXP_REASON_TOO_MANY_CONNECTIONS,
	WXP_REASON_INTERNAL_ERROR
}
wxp_close_reason_t;

typedef enum wxp_queue_object_type
{
	WXP_OBJECT_INPUT_QUEUE,
	WXP_OBJECT_OUTPUT_QUEUE,
	WXP_OBJECT_INCOMING_QUEUE,
	WXP_OBJECT_OUTCOMING_QUEUE
}
wxp_queue_object_type_t;

#pragma pack(push, 1)
typedef struct
{
	uint8_t addrlen;

	union
	{
		uint8_t eth[6];
		uint8_t addrdata[1];
	};
}
wxp_addr_t, *p_wxp_addr_t;

typedef struct _wxp_pdu
{
	uint32_t sessid;
	uint16_t type;
	uint16_t scramble;

	union
	{
		uint16_t seq;        /* For sequence numbers */
		uint16_t count;      /* For acks and repeats */
		uint32_t new_sessid; /* Server-defined sessid */
	};

	uint32_t checksum;
	uint8_t  data[0];
}
wxp_pdu_t, *p_wxp_pdu_t;
#pragma pack(pop, 1)

typedef struct _wxp_ack_header
{
	uint64_t timestamp;
	uint32_t retry_count;
	uint8_t  data[0];
}
wxp_ack_header_t, *p_wxp_ack_header_t;

typedef struct _wxp_queue
{
	int dead;

	struct packet_queue *output_q;
	struct packet_queue *outcoming_q;
	uint16_t             out_curr_seq;
	unsigned int         out_max_queue_size;

	struct packet_queue *input_q;
	struct packet_queue *incoming_q;
	uint16_t             in_curr_seq;
	unsigned int         in_max_queue_size;

#ifdef _WIN32
	HANDLE hOutputQueueChangeEvent;
	HANDLE hInputQueueChangeEvent;

	HANDLE hInputQueueReadyEvent;
	HANDLE hOutputQueueReadyEvent;

	HANDLE hOutputQueueMutex;
	HANDLE hOutcomingQueueMutex;

	HANDLE hInputQueueMutex;
	HANDLE hIncomingQueueMutex;
#endif

}
wxp_queue_t, *p_wxp_queue_t;

/* 
 *       Client              Server
 *         |                   |
 *         +------ SYN ------> | (connected: 1)
 *         |                   |
 * (con: 1)|<---- SYNACK ----- |
 *         |                   |
*/ 
typedef struct _wxp_state
{
	BOOL            server;
	BOOL            connected;
	BOOL            wait_kill;
	BOOL            reset_sent;
	BOOL            removed_from_statelist;

	/* Packets not completely read are stored in here */
	uint8_t        *half_packet;
	size_t          half_packet_size;

	int             kill_reason;  /* See this as an error code */

	uint64_t        first_syn_timestamp;
	uint32_t        suggested_sessid;
	uint32_t        sessid;
	wxp_addr_t      src;
	wxp_addr_t      dst;

	p_wxp_queue_t   queues;
	
	struct packet_queue *ack_queue;
	uint16_t             highest_ack;

	int             hysteresis_threshold_lock;    /* Flow control: max number of packets that can be sent to the backend with no ACK from remote */
	int             hysteresis_threshold_unlock;  /* Flow control: min number of ACK-pending packets that we need to have in queue to unlock outcoming queue */

#ifdef _WIN32
	HANDLE hDisposeEvent;     /* Dispose event: received when state is removed from state list */
	HANDLE hCloseEvent;       /* Close event: received when either in_closed or out_closed become TRUE */
	HANDLE hHysterEvent;      /* Hysteresis event, signaled when overflow control allows us to send */
	HANDLE hSenderThread;     /* Sender thread handle */
	DWORD  dwSenderThreadId;  /* Sender thread ID */

	HANDLE hSendEvent;        /* Send event. There's data in the output queue to send to the backend */
	HANDLE hAckQueueEvent;    /* ACK queue event. Signaled when we're ready to send acks to the net */
	HANDLE hRepeatEvent;      /* Repeat from non-acked upon request (or timer) */
	HANDLE hLostEvent;        /* Check for lost packets (signaled when packets come out of order) */

	HANDLE hConnectionEvent;  /* Wait for this when connection is done */

	HANDLE hAckQueueMutex;    /* ACK queue mutex, to protect ACK queue */

	/* Timers of different delayed actions (send data, ACKs, repeat or ask for lost packets) */
	LARGE_INTEGER hSendEventDue;
	LARGE_INTEGER hAckQueueEventDue;
	LARGE_INTEGER hRepeatEventDue;
	LARGE_INTEGER hLostEventDue;
#endif
}
wxp_state_t, *p_wxp_state_t;

typedef struct _wxp_backend
{
	uint32_t (*get_mtu)  (void *);
	int      (*sendto)   (void *, wxp_addr_t, wxp_addr_t, const void *, size_t);
	int      (*recvfrom) (void *, p_wxp_addr_t, p_wxp_addr_t, void **, size_t *);
	void     (*close)    (void *);
#ifdef _WIN32
	HANDLE   (*get_evt)  (void *);
#endif
}
wxp_backend_t, *p_wxp_backend_t;

/* Debug functions */
void wxpdbg (int, const char *, ...);

/* Packet decoding functions */
uint32_t wxp_calc_checksum (const void *, size_t);
int wxp_addrcmp (const wxp_addr_t *, const wxp_addr_t *);
wxp_addr_t wxp_get_current_remote_address (void);
uint32_t wxp_random (void);

/* Misc functions */
uint64_t wxp_get_timestamp (void);

/* Packet queue set functions */
p_wxp_queue_t wxp_queue_new (void);
void wxp_queue_lock_object (p_wxp_queue_t, wxp_queue_object_type_t);
void wxp_queue_unlock_object (p_wxp_queue_t, wxp_queue_object_type_t);
void wxp_queue_destroy_mutexes (p_wxp_queue_t);
void wxp_wait_for_object (p_wxp_queue_t, wxp_queue_object_type_t, uint32_t);
int  wxp_out_queue_reset (p_wxp_queue_t);
int  wxp_out_queue_write (p_wxp_queue_t, const void *, size_t); /* Send data to output queue and increment seqno */
int  wxp_out_queue_pick (p_wxp_queue_t, p_wxp_pdu_t *, size_t *); /* Read packet from output queue and put it in outcoming */
int  wxp_out_queue_ack_packet (p_wxp_queue_t, uint16_t); /* Remove from outcoming queue */
BOOL wxp_in_queue_empty (p_wxp_queue_t);
void wxp_signal_object (p_wxp_queue_t, wxp_queue_object_type_t);
int  wxp_in_put (p_wxp_queue_t, p_wxp_pdu_t, size_t); /* Parse incoming packet */
int  wxp_in_queue_read (p_wxp_queue_t, void **, size_t *); /* Read data from input queue */
void wxp_queue_destroy (p_wxp_queue_t);
int  packet_queue_pick_lock (p_wxp_queue_t, struct packet_queue *, wxp_queue_object_type_t, void **, size_t *);

/* State & session functions */
p_wxp_state_t wxp_state_new (void);
void wxp_state_set_waitkill (p_wxp_state_t, wxp_close_reason_t);
p_wxp_state_t wxp_state_lookup (uint32_t);
p_wxp_state_t wxp_get_new_state (void);
p_wxp_state_t wxp_state_lookup_by_init_sessid (uint32_t);
void wxp_set_new_state (p_wxp_state_t);
int  wxp_state_register (p_wxp_state_t);
void wxp_state_clear (p_wxp_state_t);
void wxp_clear_waitkill_states (void);
p_wxp_state_t wxp_get_listening_state_by_suggested_sessid (uint32_t);
void wxp_state_destroy (p_wxp_state_t);
int  wxp_add_to_dead_session_history (uint32_t);
p_wxp_state_t wxp_get_listening_state (uint32_t);
p_wxp_state_t wxp_pull_listening_state (void);
int  wxp_push_listening_state (p_wxp_state_t);
void wxp_cleanup_expired_listening_states (void);

/* PDU send functions */
int wxp_send_pdu (p_wxp_state_t, p_wxp_pdu_t, size_t);
int wxp_send_syn (wxp_addr_t, wxp_addr_t, uint32_t);
int wxp_send_synack (wxp_addr_t, wxp_addr_t, uint32_t, uint32_t);
int wxp_send_ack (wxp_addr_t, wxp_addr_t, uint32_t);
int wxp_send_rst (wxp_addr_t, wxp_addr_t, uint32_t, uint16_t);

/* TX thread functions */
int wxp_sched_ack (p_wxp_state_t, const p_wxp_pdu_t);
int wxp_sched_repeat (p_wxp_state_t);
int wxp_sched_repeat_periodically (p_wxp_state_t);
int wxp_sched_lost (p_wxp_state_t);
int wxp_sched_send (p_wxp_state_t);
int wxp_sched_send_periodically (p_wxp_state_t);

/* Flow control functions */
void wxp_wait_hysteresis_timeout (p_wxp_state_t, DWORD);

/* ACK functions */
int  wxp_remove_from_outcoming (p_wxp_state_t, const p_wxp_pdu_t, size_t);
BOOL wxp_seq_already_confirmed (p_wxp_state_t, uint16_t);
uint64_t wxp_out_get_min_timeout (p_wxp_queue_t); /* Get the minimal time before reparsing ack queue */

/* Thread functions */
int wxp_receiver_thread (void);
int wxp_sender_thread (p_wxp_state_t);

/* Backend functions */
p_wxp_backend_t wxp_get_current_backend (void);
void *wxp_get_current_backend_data (void);

#ifdef __cplusplus
}
#endif


#endif /* _WXP_WXP_STATE_H */
