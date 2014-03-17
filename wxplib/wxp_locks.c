/* 
 * wxp_locks.c: synchronization functions, mutexes, events and so on.
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

#ifdef _WIN32
static HANDLE hGlobalStateMutex;
static HANDLE hEvents[2] = {0};
static HANDLE hReceiverThread;
static HANDLE hListeningMutex;
static HANDLE hConnectionReadyEvent;
static DWORD  dwReceiverThreadId;
#endif

#ifdef _WIN32
static DWORD WINAPI
ReceiverThreadFunc (LPVOID data)
{
	wxp_receiver_thread ();

	return 0;
}
#endif

void
wxp_server_state_lock (void)
{
#ifdef _WIN32
	(void) WaitForSingleObject (hListeningMutex, INFINITE);
#endif
}

void
wxp_server_state_unlock (void)
{
#ifdef _WIN32
	(void) ReleaseMutex (hListeningMutex);
#endif
}

void
wxp_global_state_lock (void)
{
#ifdef _WIN32
	(void) WaitForSingleObject (hGlobalStateMutex, INFINITE);
#endif
}

void
wxp_global_state_unlock (void)
{
#ifdef _WIN32
	(void) ReleaseMutex (hGlobalStateMutex);
#endif
}

void
wxp_ack_queue_lock (p_wxp_state_t state)
{
#ifdef _WIN32
	(void) WaitForSingleObject (state->hAckQueueMutex, INFINITE);
#endif
}

void
wxp_ack_queue_unlock (p_wxp_state_t state)
{
#ifdef _WIN32
	(void) ReleaseMutex (state->hAckQueueMutex);
#endif
}

/* New data is directly signaled by thread */
void
wxp_signal_new_state (void)
{
#ifdef _WIN32
	(void) SetEvent (hEvents[WXP_EVENT_NEW_STATE]);
#endif
}

int
wxp_wait_for_event (void)
{
	int result;
#ifdef _WIN32
	result = WaitForMultipleObjects (2, hEvents, FALSE, INFINITE);

	if (result - WAIT_OBJECT_0 >= 0 && result - WAIT_OBJECT_0 < 2)
		return result - WAIT_OBJECT_0;

	return -1;
#endif
}

int
wxp_wait_for_sender_event (p_wxp_state_t state)
{
	int result;
	int evno;

#ifdef _WIN32
	/* These ones are all timers */
	HANDLE hEvents[4] = {state->hAckQueueEvent, state->hRepeatEvent, state->hLostEvent, state->hSendEvent};
	LARGE_INTEGER *pDues[4] = {&state->hAckQueueEventDue, &state->hRepeatEventDue, &state->hLostEventDue, &state->hSendEventDue};

	result = WaitForMultipleObjects (4, hEvents, FALSE, INFINITE);

	if ((evno = result - WAIT_OBJECT_0) >= 0 && result - WAIT_OBJECT_0 < 4)
	{
		pDues[evno]->QuadPart = 0LL;
		return evno;
	}
	return -1;
#endif
}

int
wxp_wait_connection_completion (p_wxp_state_t state)
{
#ifdef _WIN32
	if (WaitForSingleObject (state->hConnectionEvent, WXP_DEFAULT_CONN_TIMEOUT) == ERROR_SUCCESS)
		return 0;

	return -1;
#endif
}

void
wxp_signal_connection_completion (p_wxp_state_t state)
{
#ifdef _WIN32
	(void) SetEvent (state->hConnectionEvent);
#endif
}

void
wxp_signal_new_connection (void)
{
#ifdef _WIN32
	(void) SetEvent (hConnectionReadyEvent);
#endif
}

void
wxp_wait_new_connection (void)
{
#ifdef _WIN32
	(void) WaitForSingleObject (hConnectionReadyEvent, INFINITE);
#endif
}

int
wxp_sender_event_is_signaled (p_wxp_state_t state, int event)
{
	int result;

#ifdef _WIN32
	HANDLE hEvents[4] = {state->hAckQueueEvent, state->hRepeatEvent, state->hLostEvent, state->hSendEvent};
	LARGE_INTEGER *pDues[4] = {&state->hAckQueueEventDue, &state->hRepeatEventDue, &state->hLostEventDue, &state->hSendEventDue};

	if (result = (WaitForSingleObject (hEvents[event], 0) != WAIT_TIMEOUT))
		pDues[event]->QuadPart = 0LL;
#endif

	return result;
}

void
wxp_wait_disposal (p_wxp_state_t state)
{
#ifdef _WIN32
	(void) WaitForSingleObject (state->hDisposeEvent, INFINITE);
#endif
}

void
wxp_signal_disposal (p_wxp_state_t state)
{
#ifdef _WIN32
	(void) SetEvent (state->hDisposeEvent);
#endif
}

void
wxp_wait_hysteresis_timeout (p_wxp_state_t state, DWORD timeout)
{
#ifdef _WIN32
	WaitForSingleObject (state->hHysterEvent, timeout);
#endif
}

void
wxp_wait_hysteresis (p_wxp_state_t state)
{
#ifdef _WIN32
	WaitForSingleObject (state->hHysterEvent, INFINITE);
#endif
}

void
wxp_signal_hysteresis (p_wxp_state_t state)
{
#ifdef _WIN32
	SetEvent (state->hHysterEvent);
#endif
}

int
wxp_init_locks (const p_wxp_backend_t backend, void *backend_data)
{
#ifdef _WIN32
	if ((hGlobalStateMutex = CreateMutex (NULL, FALSE, NULL)) == NULL)
		return -1;

	if ((hEvents[WXP_EVENT_NEW_STATE] = CreateEvent (NULL, FALSE, FALSE, NULL)) == NULL)
	{
		CloseHandle (hGlobalStateMutex);
		return -1;
	}

	if ((hEvents[WXP_EVENT_NEW_DATA] = (backend->get_evt) (backend_data)) == NULL)
	{
		CloseHandle (hEvents[WXP_EVENT_NEW_STATE]);
		CloseHandle (hGlobalStateMutex);
		return -1;
	}

	if ((hConnectionReadyEvent = CreateEvent (NULL, FALSE, FALSE, NULL)) == NULL)
	{
		CloseHandle (hEvents[WXP_EVENT_NEW_DATA]);
		CloseHandle (hEvents[WXP_EVENT_NEW_STATE]);
		CloseHandle (hGlobalStateMutex);
	}

	hReceiverThread = CreateThread (NULL, 0, ReceiverThreadFunc, NULL, 0, &dwReceiverThreadId);

#endif

	return 0;
}
