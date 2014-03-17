/* 
 * queue.h: prototypes and definition for packet queues.
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
#ifndef _WXP_QUEUE_H
#define _WXP_QUEUE_H

#include <sys/types.h>

struct qel
{
	struct qel *next, *prev;

	size_t size;
	void *data;
};

struct packet_queue
{
	size_t      count;
	struct qel *head;
	struct qel *tail;
};

struct packet_queue *packet_queue_new (void);
int  packet_queue_put (struct packet_queue *, const void *, size_t);
int  packet_queue_pick (struct packet_queue *, void **, size_t *);
int  packet_queue_peek (struct packet_queue *, void **, size_t *);
void packet_queue_destroy (struct packet_queue *);
int  packet_queue_is_empty (struct packet_queue *);
void packet_queue_remove (struct packet_queue *, struct qel *);
void packet_queue_walk (struct packet_queue *, void (*) (void *, struct qel *), void *);

#endif /* _WXP_QUEUE_H */

