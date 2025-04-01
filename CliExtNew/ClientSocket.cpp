#include "stdafx.h"
#include "ClientSocket.h"
#include "HWID.h"
#include "Crypt.h"

extern HMODULE g_Engine;

DWORD g_CryptPacketFunction = 0;
UINT g_ChecksumKey = 0;
UINT g_LastChecksum = 0;
volatile LONG g_PacketCounter = 4;

typedef int (*__VAssemble)(PBYTE, int, const char*, va_list);
__VAssemble VAssemble = 0;

#pragma optimize("", off)

void CClientSocket::Init()
{
	VIRTUALIZER_START;

	VAssemble = (__VAssemble)((UINT)g_Engine + 0x68B6);

	VIRTUALIZER_END;
}


int Assemble(PBYTE buff, int buffSize, const char* format ...)
{
	va_list va;
	va_start(va, format);

	int ret = VAssemble(buff, buffSize, format, va);

	va_end(va);

	return ret;
};

#pragma optimize("", on)

void CClientSocket::Send(int len, char *buff)
{
	try
	{
		DWORD funcAddr = (*(LPDWORD)this);
		funcAddr += 0x68;
		funcAddr = (*(LPDWORD)funcAddr);

		typedef void (__cdecl *f)(CClientSocket*, const char*, int, char*);
		f((PVOID)funcAddr)(this, "b", len, buff);
	}catch(...)
	{
	}
}