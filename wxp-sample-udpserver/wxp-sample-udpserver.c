/* 
 * wxp-sample-udpserver.c: sample UDP server, listens for a reverse shell.
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

HANDLE hGlobalLock;
HANDLE hReady, hRead;
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

	while ((local_got = recvfrom (sck, localbuffer, UDP_MTU, 0, (struct sockaddr *) &recv_addr, &addrlen)) >= 1)
	{
		WaitForSingleObject (hGlobalLock, INFINITE);

		memcpy (buffer, localbuffer, local_got);

		got_bytes = local_got;
		send_addr = recv_addr;

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

	return 0;
}

int
udp_recvfrom (void *backend_data, p_wxp_addr_t src, p_wxp_addr_t dst, void **data, size_t *size)
{
	WaitForSingleObject (hRead, INFINITE);
	WaitForSingleObject (hGlobalLock, INFINITE);

	if (got_bytes < 1)
	{
		ReleaseMutex (hGlobalLock);
		return -1;
	}

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

DWORD WINAPI
readStuff (LPVOID lpState)
{
	int size;
	char buff[UDP_MTU];

	p_wxp_state_t state = (p_wxp_state_t) lpState;

	while ((size = wxp_read (state, buff, sizeof (buff) - 1)) != -1)
	{
		buff[size] = 0;

		SetConsoleTextAttribute (GetStdHandle (STD_ERROR_HANDLE), 15);

		fwrite (buff, size, 1, stdout);

		fflush (stdout);

		SetConsoleTextAttribute (GetStdHandle (STD_ERROR_HANDLE), 10);
	}

	return 0;
}

p_wxp_backend_t
get_udp_backend (const char *appname)
{
	static wxp_backend_t backend;
	static WSADATA wsaData;

	WSAStartup (MAKEWORD (2, 2), &wsaData);

	/* Prepare client socket */
	if ((sck = udp_open (9999)) == -1)
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
	p_wxp_backend_t backend;
	wxp_addr_t ignore = {0};
	p_wxp_state_t state;
	char buff[1024];
	DWORD dwId;

	backend = get_udp_backend (argv[0]);
	hRead   = CreateEvent (NULL, FALSE, FALSE, NULL);
	hReady  = CreateEvent (NULL, FALSE, FALSE, NULL);

	hGlobalLock = CreateMutex (NULL, FALSE, NULL);

	CreateThread (NULL, 0, reader_thread, NULL, 0, &dwId);

	if (wxp_init (ignore, backend, NULL) == -1)
	{
		fprintf (stderr, "%s: cannot init: %d\n", argv[0], GetLastError ());
		getchar ();
		return 0;
	}

	printf ("Server started, waiting for remote connection . . . ");
	fflush (stdout);

	if ((state = wxp_listen (ignore)) == NULL)
	{
		fprintf (stderr, "%s: cannot listen: %d\n", argv[0], GetLastError ());
		getchar ();
		return 0;
	}

	printf ("got connection: %p\n", state->sessid);

	CreateThread (NULL, 0, readStuff, state, 0, &dwId);

	while (fgets (buff, sizeof (buff), stdin) != NULL)
	{
		if (wxp_write (state, buff, strlen (buff)) == -1)
			break;
	}

	fprintf (stderr, "%s: punt!\n", argv[0]);

	wxp_close (state);

	getchar ();

	return 0;
}

