#include "stdafx.h"
#include "FastLoadNpc.h"

void CFastLoadNPC::Init()
{
	TCHAR file[260] = { 0 };
	GetCurrentDirectory(MAX_PATH,file);
	lstrcat(file, _T("\\l2npc.ini"));
	const TCHAR* section = _T("FastLoadNpc");
	bool m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, file) ? true : false;

	if(m_Enabled)
		WriteDWORD(0x6B8E80, (DWORD)TimerExpired);
}

void CFastLoadNPC::TimerExpired(UINT64 pNpcMakerDB, int nTimerId)
{
	typedef bool (*f)(UINT64);
	typedef bool (*t)(UINT64, int, int);
	typedef void (*e)(UINT64, int);
	
	if(nTimerId == 1)
	{
		while( f(0x5517D0L)(pNpcMakerDB) ) { /*Sleep(1);*/ } //ProcessOneNpcMaker
		e(0x551A10L)(pNpcMakerDB, 1);
	}
	else
	{
		while( f(0x551BF0L)(pNpcMakerDB) ) { /*Sleep(1);*/ } //ProcessOneNpcMakerEx
	}

	//g_Log.Add(LogError, "[%s] Test Timer[%d]!", __FUNCTION__, nTimerId);
}