#include "StdAfx.h"
#include "EventStats.h"
#include "DB.h"
#include "HtmlCache.h"
#include "PlayerAction.h"

CEventStats g_EventStats;

void CEventStats::Init()
{
	m_Enabled = FALSE;

	LoadINI();
	if(m_Enabled)
	{
		g_Log.Add(CLog::Blue, "[%s] Feature is enabled.", __FUNCTION__);
	}
}

/*
[EventStats]
;Enables the counting of kills/deaths during Events
Enabled=0
;Refresh time - how often it will refresh the status
RefreshTimeout=3600
*/

void CEventStats::LoadINI()
{
	const TCHAR* section = _T("EventStats");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);
	m_RefreshTimeout = GetPrivateProfileInt(section, _T("RefreshTimeout"), 0, g_ConfigFile);
}