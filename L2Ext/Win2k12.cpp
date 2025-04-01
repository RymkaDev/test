#include "StdAfx.h"
#include "Win2k12.h"
#include "DB.h"

CWin2k12 g_Win2k12;

void CWin2k12::Init()
{
	m_Enabled = FALSE;

	LoadINI();
	if(m_Enabled)
	{
		m_Done = FALSE;
		//beta
		BYTE OrgBytes8[5] = {0xE8, 0x9E, 0xC8, 0x19, 0x00};
		g_HookManager.WriteCall(0x64512D, CWin2k12::AddToStatusWindow, 0, OrgBytes8);
	}
}

void CWin2k12::LoadINI()
{
	const TCHAR* section = _T("Win2k12");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 1, g_ConfigFile);
}

void CWin2k12::TimerExpired()
{
	guard;

	if(m_Enabled)
	{
		if(!m_Done)
		{
			//Shutdown Server
			ExitProcess(0);
		}
	}
	unguard;
}

void CWin2k12::AddToStatusWindow(LPVOID pWindow, int nLine, PWCHAR format, int nCount1, int nCount2, int nCount3, int nCount4)
{
	typedef void (*f)(LPVOID, int, PWCHAR, int, int, int, int);
	//Our new info
	static PWCHAR newFormat = L"Elapsed Time: %d d %02d h %02d m %02d s";

	if( nCount3 == 4 && (nCount4 == 0 || nCount4 == 1) )
	{
		g_Win2k12.TimerExpired();
	}
	f(0x7E19D0L)(pWindow, nLine, newFormat, nCount1, nCount2, nCount3, nCount4); //TODO
}
