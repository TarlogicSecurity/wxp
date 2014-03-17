/* 
 * redirect.c: redirect a console process with two threads. Yep, there's
 * no better way to implement this. As far as I know, at least.
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

/* This file is Windows. Windows, as an adjective. Enough said. */

#include <Windows.h>

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <io.h>
#include <assert.h>
#include <Psapi.h>

#include <wxp.h>

#define PIPE_BUFFER_SIZE 4096

typedef struct _CHILDINFO
{
	p_wxp_state_t pwState;

	HANDLE hChildPipeRead;
	HANDLE hChildStdouterr;
	HANDLE hChildPipeWrite;
	HANDLE hChildStdin;
	HANDLE hProcess;

	PROCESS_INFORMATION piInfo;
	BOOL holdsPiInfo;
}
CHILD_INFO;

void
DestroyChildInfo (CHILD_INFO *ciInfo)
{
	if (ciInfo->hChildPipeRead != NULL)
		CloseHandle (ciInfo->hChildPipeRead);

	if (ciInfo->hChildPipeWrite != NULL)
		CloseHandle (ciInfo->hChildPipeWrite);

	if (ciInfo->hChildStdouterr != NULL)
		CloseHandle (ciInfo->hChildStdouterr);

	if (ciInfo->hChildStdin != NULL)
		CloseHandle (ciInfo->hChildStdin);

	free (ciInfo);
}

CHILD_INFO *
CreateChildInfo (p_wxp_state_t state)
{
	CHILD_INFO * ciNew;
	char stdoutPipeName[100];
	char stdinPipeName[100];

	if ((ciNew = (CHILD_INFO *) malloc (sizeof (CHILD_INFO))) == NULL)
		return NULL;

	ZeroMemory (ciNew, sizeof (CHILD_INFO));

	ciNew->holdsPiInfo = FALSE;
	ciNew->pwState = state;

	sprintf_s (stdoutPipeName, 100, "\\\\.\\pipe\\wxp-stdout-%08x", GetCurrentProcessId ());
	sprintf_s (stdinPipeName,  100, "\\\\.\\pipe\\wxp-stdin-%08x",  GetCurrentProcessId ());

	if ((ciNew->hChildPipeRead = CreateNamedPipeA (stdoutPipeName, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 1, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 0, NULL)) == INVALID_HANDLE_VALUE)
	{
		DestroyChildInfo (ciNew);

		return NULL;
	}

	SetHandleInformation (ciNew->hChildPipeRead, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

	if ((ciNew->hChildStdouterr = CreateFileA (stdoutPipeName, GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL)) == INVALID_HANDLE_VALUE)
	{
		DestroyChildInfo (ciNew);

		return NULL;
	}

	if ((ciNew->hChildPipeWrite = CreateNamedPipeA (stdinPipeName, PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 1, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 0, NULL)) == INVALID_HANDLE_VALUE)
	{
		DestroyChildInfo (ciNew);

		return NULL;
	}

	SetHandleInformation (ciNew->hChildPipeWrite, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);


	if ((ciNew->hChildStdin = CreateFileA (stdinPipeName, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL)) == INVALID_HANDLE_VALUE)
	{
		DestroyChildInfo (ciNew);

		return NULL;
	}

	return ciNew;
}

int
CreateRedirectedConsoleProcess (CHILD_INFO *ciInfo, const char *path, const char *name)
{
	STARTUPINFOA siInfo;
	SECURITY_ATTRIBUTES sAttr;

	char *namedup = NULL;

	ZeroMemory (&siInfo, sizeof (STARTUPINFOA));

	siInfo.cb          = sizeof (STARTUPINFOA);
	siInfo.lpReserved  = NULL;
	siInfo.lpDesktop   = NULL;
	siInfo.lpTitle     = NULL;
	siInfo.cbReserved2 = 0;
	siInfo.lpReserved2 = NULL;
	siInfo.dwFlags     = STARTF_USESTDHANDLES | STARTF_FORCEOFFFEEDBACK;
	siInfo.hStdInput   = ciInfo->hChildPipeRead;
	siInfo.hStdOutput  = ciInfo->hChildPipeWrite;
	siInfo.hStdError   = ciInfo->hChildPipeWrite;
	
	sAttr.nLength = sizeof (sAttr);
	sAttr.lpSecurityDescriptor = NULL;
	sAttr.bInheritHandle = TRUE;

	if (name != NULL)
		if ((namedup = _strdup (name)) == NULL)
			return -1;

	if (!CreateProcessA (
		path, 
		namedup, 
		&sAttr,
		NULL,
		TRUE,
		CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS,
		NULL,
		NULL,
		&siInfo,
		&ciInfo->piInfo))
		return -1;
	
	ciInfo->holdsPiInfo = TRUE;

	free (namedup);

	return 0;
}

DWORD WINAPI 
OutputRedirectorThread (LPVOID lpParam)
{
	CHILD_INFO *ciInfo = (CHILD_INFO *) lpParam;
	char buffer[1024];
	DWORD byteCount;
	
	while (ReadFile (ciInfo->hChildStdin, buffer, sizeof (buffer), &byteCount, NULL))
		(void) wxp_write (ciInfo->pwState, buffer, byteCount);

	return 0;
}


DWORD WINAPI
InputRedirectorThread (LPVOID lpParam)
{
	CHILD_INFO *ciInfo = (CHILD_INFO *) lpParam;
	DWORD bytesWritten;
	char buffer[1024];
	int byteCount;

	for (;;)
	{
		if ((byteCount = wxp_read (ciInfo->pwState, buffer, sizeof (buffer))) < 1)
			break;

		if (!WriteFile (ciInfo->hChildStdouterr, buffer, byteCount, &bytesWritten, NULL))
			break;
	}

	return 0;
}


int
StartRedirectionLoop (CHILD_INFO *ciInfo)
{
	DWORD outputThreadId;
	DWORD inputThreadId;
	HANDLE outputThreadHandle;
	HANDLE inputThreadHandle;

	if ((outputThreadHandle = CreateThread (NULL, 0, OutputRedirectorThread, (LPVOID) ciInfo, 0, &outputThreadId)) == INVALID_HANDLE_VALUE)
		return -1;

	if ((inputThreadHandle = CreateThread (NULL, 0, InputRedirectorThread, (LPVOID) ciInfo, 0, &inputThreadId)) == INVALID_HANDLE_VALUE)
		return -1;

	WaitForSingleObject (ciInfo->piInfo.hProcess, INFINITE);

	TerminateThread (outputThreadHandle, 0);
	TerminateThread (inputThreadHandle,  0);

	return 0;
}

int
ExecuteRedirected (p_wxp_state_t state, const char *path)
{
	CHILD_INFO *ciInfo;
	int ret;

	if ((ciInfo = CreateChildInfo (state)) == NULL)
	{
		fprintf (stderr, "ExecuteRedirected: cannot create child info\n");
		return -1;
	}

	if (CreateRedirectedConsoleProcess (ciInfo, path, path) == -1)
	{
		fprintf (stderr, "ExecuteRedirected: cannot create redirected console process\n");
		DestroyChildInfo (ciInfo);
		return -1;
	}

	ret = StartRedirectionLoop (ciInfo);

	DestroyChildInfo (ciInfo);

	return ret;
}