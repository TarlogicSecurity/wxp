/* 
 * queue.c: generic packet queue implementation.
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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "queue.h"

struct packet_queue *
packet_queue_new (void)
{
	struct packet_queue *queue;

	if ((queue = (struct packet_queue *) calloc (1, sizeof (struct packet_queue))) == NULL)
		return NULL;

	return queue;
}

int
packet_queue_put (struct packet_queue *queue, const void *data, size_t size)
{
	struct qel *qel;

	if (queue == NULL)
		return -1;

	if ((qel = (struct qel *) calloc (1, sizeof (struct qel))) == NULL)
		return -1;

	if ((qel->data = calloc (1, size)) == NULL)
	{
		free (qel);
		return -1;
	}

	memcpy (qel->data, data, size);

	qel->size = size;

	if (queue->tail != NULL)
		queue->tail->next = qel;

	qel->prev = queue->tail;

	queue->tail = qel;

	if (queue->head == NULL)
		queue->head = qel;

	assert ((queue->head && queue->tail) || (!queue->head && !queue->tail));

	++queue->count;

	return 0;
}

#include <stdio.h>

int
packet_queue_peek (struct packet_queue *queue, void **data, size_t *size)
{
	struct qel *qel;

	if (queue == NULL)
		return -1;

	if ((qel = queue->head) == NULL)
		return -1;

	*data = queue->head->data;
	*size = queue->head->size;

	assert ((queue->head && queue->tail) || (!queue->head && !queue->tail));

	return 0;
}

int
packet_queue_pick (struct packet_queue *queue, void **data, size_t *size)
{
	struct qel *qel;

	if (queue == NULL)
		return -1;

	if ((qel = queue->head) == NULL)
		return -1;

	
	*data = queue->head->data;
	*size = queue->head->size;

	queue->head = queue->head->next;
	
	if (queue->head == NULL)
		queue->tail = NULL;
	else
		queue->head->prev = NULL;

	free (qel);

	--queue->count;

	assert ((queue->head && queue->tail) || (!queue->head && !queue->tail));

	return 0;
}

void
packet_queue_destroy (struct packet_queue *queue)
{
	void *data;
	size_t size;

	if (queue == NULL)
		return;

	assert ((queue->head && queue->tail) || (!queue->head && !queue->tail));


	while (packet_queue_pick (queue, &data, &size) != -1)
		free (data);
	
	free (queue);
}

int
packet_queue_is_empty (struct packet_queue *queue)
{
	if (queue == NULL)
		return 1;

	return queue->head == NULL;
}

void
packet_queue_remove (struct packet_queue *queue, struct qel *curr)
{
	if (queue == NULL)
		return;

	if (curr == queue->head)
		queue->head = curr->next;

	if (curr == queue->tail)
		queue->tail = curr->prev;

	if (curr->next != NULL)
		curr->next->prev = curr->prev;

	if (curr->prev != NULL)
		curr->prev->next = curr->next;

	free (curr->data);
	free (curr);

	assert ((queue->head && queue->tail) || (!queue->head && !queue->tail));

	--queue->count;
}

void
packet_queue_walk (struct packet_queue *queue, void (*callback) (void *, struct qel *), void *data)
{
	struct qel *curr;

	if (queue == NULL)
		return;

	curr = queue->head;

	assert ((queue->head && queue->tail) || (!queue->head && !queue->tail));

	while (curr)
	{
		(callback) (data, curr);
		curr = curr->next;
	}
}
