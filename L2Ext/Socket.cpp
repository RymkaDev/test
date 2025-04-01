#include "StdAfx.h"

extern double g_ZonePvPAutoAttackRejunteDamage;

User* CSocket::GetUser(CSocket* pSocket)
{
	typedef User* (*f)(CSocket*);
	return f(0x004012C0L)(pSocket);
}

bool CSocket::ValidUserSocket()
{
	if(this)
	{
		try
		{
			if(*(DWORD*)this == 0xA8EE78)
				if(this->s != -1)
					return true;
		}
		catch(...)
		{
			return false;
		}
	}
	return false;
}

CUserSocket* CSocket::CastUserSocket()
{
	if(this)
	{
		try
		{
			if(*(LPDWORD)this == 0xA8EE78) //CUserSocket
				return (CUserSocket*)this;

		}catch(...)
		{
		}
	}
	return 0;
}

void CSocket::Send(const char *format, ...)
{
	typedef void (*f)(CSocket*, const char*, va_list va);
	
	va_list va;
	va_start(va, format);
	f(0x7D5D40)(this, format, va);
	va_end(va);
}


void CSocket::SendDamage(CSocket* instance, const char *format, ...)
{
	typedef void (*f)(CSocket*, const char*, va_list va);
	va_list va;
	va_list va2 = va;

	va_start(va, format);
	va_start(va2, format);

	INT32 va_arg (va, DWORD);
	va_arg (va, DWORD);
	va_arg (va, DWORD);
	va_arg (va, DWORD);
	va_arg (va, PWCHAR);
	va_arg (va, DWORD);
	INT32 hit = va_arg(va, DWORD);

	//g_Log.Add(CLog::Blue, "11111[%d][%f]", hit, g_ZonePvPAutoAttackRejunteDamage);
	if (hit != g_ZonePvPAutoAttackRejunteDamage)
	{
		f(0x7D5D40)(instance, format, va2);
	}
	va_end(va2);
	va_end(va);
}

void CSocket::SendDamage2(CSocket* instance, const char *format, ...)
{
	typedef void (*f)(CSocket*, const char*, va_list va);
	va_list va;
	va_list va2 = va;

	va_start(va, format);
	va_start(va2, format);

	INT32 va_arg (va, DWORD);
	va_arg (va, DWORD);
	va_arg (va, DWORD);
	va_arg (va, DWORD);
	INT32 hit = va_arg(va, DWORD);

	//g_Log.Add(CLog::Blue, "11111[%d][%f]", hit, g_ZonePvPAutoAttackRejunteDamage);

	if (hit != g_ZonePvPAutoAttackRejunteDamage)
	{
		f(0x7D5D40)(instance, format, va2);
	}
	va_end(va2);
	va_end(va);
}


void CSocket::SendUseItem(CSocket* instance, const char *format, ...)
{
	typedef void (*f)(CSocket*, const char*, va_list va);
	va_list va;
	va_list va2 = va;

	va_start(va, format);
	va_start(va2, format);

	INT32 va_arg (va, DWORD);
	va_arg (va, DWORD);
	va_arg (va, DWORD);
	va_arg (va, DWORD);
	INT32 nItemID = va_arg (va, INT32);

	if (nItemID != 1835 && nItemID != 1463 && nItemID != 1464 && nItemID != 1465 && nItemID != 1466 && nItemID != 1467 &&  nItemID != 2509 &&  nItemID != 2510 &&  nItemID != 2511 &&  nItemID != 2512 &&  nItemID != 2513 &&  nItemID != 2514 && nItemID != 3947 && nItemID != 3948 && nItemID != 3949 && nItemID != 3950 && nItemID != 3951 && nItemID != 3952)
	{
		f(0x7D5D40)(instance, format, va2);
	}
	va_end(va2);
	va_end(va);
}

void CSocket::SendV(const char *format, va_list va)
{
	typedef void (*f)(CSocket*, const char*, va_list);
	f(0x007D5D40L)(this, format, va);
}

void CSocket::Send(CServerPacket *pck)
{
	if(this)
	{
		Send("b", pck->GetSize(), pck->GetBuff());
	}
}

in_addr *CSocket::GetAddress(in_addr *pAddr)
{
	typedef in_addr*(*_f)(CSocket*, in_addr *);
	_f f = (_f) 0x007D53B0;
	return f(this, pAddr);
}


