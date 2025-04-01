#include "StdAfx.h"
#include "OlympiadStatus.h"
#include "DB.h"
#include "HtmlCache.h"
#include "PlayerAction.h"
#include "OlympiadSystem.h"

COlympiadStatusPages g_OlympiadStatus;

void COlympiadStatusPages::Init()
{
	m_Enabled = FALSE;

	LoadINI();
	if(m_Enabled)
	{
		g_Log.Add(CLog::Blue, "[%s] Feature is enabled, refresh timeout [%d] second(s).", __FUNCTION__, m_RefreshTimeout);
		m_RefreshTime = time(0) + m_RefreshTimeout;
		g_DB.RequestLoadOlympiad88();
		g_DB.RequestLoadOlympiad89();
		g_DB.RequestLoadOlympiad90();
		g_DB.RequestLoadOlympiad91();
		g_DB.RequestLoadOlympiad92();
		g_DB.RequestLoadOlympiad93();
		g_DB.RequestLoadOlympiad94();
		g_DB.RequestLoadOlympiad95();
		g_DB.RequestLoadOlympiad96();
		g_DB.RequestLoadOlympiad97();
		g_DB.RequestLoadOlympiad98();
		g_DB.RequestLoadOlympiad99();
		g_DB.RequestLoadOlympiad100();
		g_DB.RequestLoadOlympiad101();
		g_DB.RequestLoadOlympiad102();
		g_DB.RequestLoadOlympiad103();
		g_DB.RequestLoadOlympiad104();
		g_DB.RequestLoadOlympiad105();
		g_DB.RequestLoadOlympiad106();
		g_DB.RequestLoadOlympiad107();
		g_DB.RequestLoadOlympiad108();
		g_DB.RequestLoadOlympiad109();
		g_DB.RequestLoadOlympiad110();
		g_DB.RequestLoadOlympiad111();
		g_DB.RequestLoadOlympiad112();
		g_DB.RequestLoadOlympiad113();
		g_DB.RequestLoadOlympiad114();
		g_DB.RequestLoadOlympiad115();
		g_DB.RequestLoadOlympiad116();
		g_DB.RequestLoadOlympiad117();
		g_DB.RequestLoadOlympiad118();
	}
}

/*
[OlympiadStatus]
;Enables new bypass: "bypass -h rb_status?page=0" - will show olympiad status
Enabled=0
;Refresh time - how often it will refresh the status
RefreshTimeout=60
;If Enabled, it will update points only when olympiad runs (Recommended: On)
RefreshOlympiadWhenRunning=0
*/

void COlympiadStatusPages::LoadINI()
{
	const TCHAR* section = _T("OlympiadStatus");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);
	m_RefreshTimeout = GetPrivateProfileInt(section, _T("RefreshTimeout"), 0, g_ConfigFile);
	m_RefreshOlyRunning = GetPrivateProfileInt(section, _T("RefreshOlympiadWhenRunning"), 0, g_ConfigFile);

	m_LoadCustom = true;
}

void COlympiadStatusPages::RequestStatusOly(User *pUser, UINT nClass)
{
	guard;
	if( nClass == 88 ) { RequestStatusOly88(pUser, 0); }
	else if( nClass == 89 ) { RequestStatusOly89(pUser, 0); }
	else if( nClass == 90 ) { RequestStatusOly90(pUser, 0); }
	else if( nClass == 91 ) { RequestStatusOly91(pUser, 0); }
	else if( nClass == 92 ) { RequestStatusOly92(pUser, 0); }
	else if( nClass == 93 ) { RequestStatusOly93(pUser, 0); }
	else if( nClass == 94 ) { RequestStatusOly94(pUser, 0); }
	else if( nClass == 95 ) { RequestStatusOly95(pUser, 0); }
	else if( nClass == 96 ) { RequestStatusOly96(pUser, 0); }
	else if( nClass == 97 ) { RequestStatusOly97(pUser, 0); }
	else if( nClass == 98 ) { RequestStatusOly98(pUser, 0); }
	else if( nClass == 99 ) { RequestStatusOly99(pUser, 0); }
	else if( nClass == 100 ) { RequestStatusOly100(pUser, 0); }
	else if( nClass == 101 ) { RequestStatusOly101(pUser, 0); }
	else if( nClass == 102 ) { RequestStatusOly102(pUser, 0); }
	else if( nClass == 103 ) { RequestStatusOly103(pUser, 0); }
	else if( nClass == 104 ) { RequestStatusOly104(pUser, 0); }
	else if( nClass == 105 ) { RequestStatusOly105(pUser, 0); }
	else if( nClass == 106 ) { RequestStatusOly106(pUser, 0); }
	else if( nClass == 107 ) { RequestStatusOly107(pUser, 0); }
	else if( nClass == 108 ) { RequestStatusOly108(pUser, 0); }
	else if( nClass == 109 ) { RequestStatusOly109(pUser, 0); }
	else if( nClass == 110 ) { RequestStatusOly110(pUser, 0); }
	else if( nClass == 111 ) { RequestStatusOly111(pUser, 0); }
	else if( nClass == 112 ) { RequestStatusOly112(pUser, 0); }
	else if( nClass == 113 ) { RequestStatusOly113(pUser, 0); }
	else if( nClass == 114 ) { RequestStatusOly114(pUser, 0); }
	else if( nClass == 115 ) { RequestStatusOly115(pUser, 0); }
	else if( nClass == 116 ) { RequestStatusOly116(pUser, 0); }
	else if( nClass == 117 ) { RequestStatusOly117(pUser, 0); }
	else if( nClass == 118 ) { RequestStatusOly118(pUser, 0); }
	else { }

	unguard;
}

void COlympiadStatusPages::RequestStatusOly88(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{

		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";

		m_Lock.Enter();
		if(m_PagesOly88.size() > 0 && page < m_PagesOly88.size())
		{
			html = m_PagesOly88[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_88.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly89(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly89.size() > 0 && page < m_PagesOly89.size())
		{
			html = m_PagesOly89[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_89.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly90(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly90.size() > 0 && page < m_PagesOly90.size())
		{
			html = m_PagesOly90[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_90.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly91(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly91.size() > 0 && page < m_PagesOly91.size())
		{
			html = m_PagesOly91[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_91.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly92(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly92.size() > 0 && page < m_PagesOly92.size())
		{
			html = m_PagesOly92[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_92.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly93(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly93.size() > 0 && page < m_PagesOly93.size())
		{
			html = m_PagesOly93[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_93.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly94(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly94.size() > 0 && page < m_PagesOly94.size())
		{
			html = m_PagesOly94[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_94.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly95(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly95.size() > 0 && page < m_PagesOly95.size())
		{
			html = m_PagesOly95[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_95.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly96(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly96.size() > 0 && page < m_PagesOly96.size())
		{
			html = m_PagesOly96[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_96.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly97(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly97.size() > 0 && page < m_PagesOly97.size())
		{
			html = m_PagesOly97[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_97.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly98(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly98.size() > 0 && page < m_PagesOly98.size())
		{
			html = m_PagesOly98[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_98.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly99(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly99.size() > 0 && page < m_PagesOly99.size())
		{
			html = m_PagesOly99[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_99.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly100(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly100.size() > 0 && page < m_PagesOly100.size())
		{
			html = m_PagesOly100[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_100.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly101(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly101.size() > 0 && page < m_PagesOly101.size())
		{
			html = m_PagesOly101[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_101.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly102(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly102.size() > 0 && page < m_PagesOly102.size())
		{
			html = m_PagesOly102[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_102.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly103(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly103.size() > 0 && page < m_PagesOly103.size())
		{
			html = m_PagesOly103[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_103.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly104(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly104.size() > 0 && page < m_PagesOly104.size())
		{
			html = m_PagesOly104[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_104.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly105(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly105.size() > 0 && page < m_PagesOly105.size())
		{
			html = m_PagesOly105[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_105.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly106(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly106.size() > 0 && page < m_PagesOly106.size())
		{
			html = m_PagesOly106[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_106.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly107(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly107.size() > 0 && page < m_PagesOly107.size())
		{
			html = m_PagesOly107[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_107.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly108(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly108.size() > 0 && page < m_PagesOly108.size())
		{
			html = m_PagesOly108[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_108.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly109(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly109.size() > 0 && page < m_PagesOly109.size())
		{
			html = m_PagesOly109[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_109.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly110(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly110.size() > 0 && page < m_PagesOly110.size())
		{
			html = m_PagesOly110[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_110.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly111(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly111.size() > 0 && page < m_PagesOly111.size())
		{
			html = m_PagesOly111[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_111.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly112(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly112.size() > 0 && page < m_PagesOly112.size())
		{
			html = m_PagesOly112[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_112.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly113(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly113.size() > 0 && page < m_PagesOly113.size())
		{
			html = m_PagesOly113[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_113.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly114(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly114.size() > 0 && page < m_PagesOly114.size())
		{
			html = m_PagesOly114[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_114.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly115(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly115.size() > 0 && page < m_PagesOly115.size())
		{
			html = m_PagesOly115[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_115.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly116(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly116.size() > 0 && page < m_PagesOly116.size())
		{
			html = m_PagesOly116[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_116.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly117(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly117.size() > 0 && page < m_PagesOly117.size())
		{
			html = m_PagesOly117[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_117.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::RequestStatusOly118(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><table width=270 border=0 cellpadding=0 cellspacing=0><tr><td width=90 height=20 align=center><button value=\"Back\" action=\"link olympiad_ranking_extra.htm\" width=191 height=30 back=\"OlympiadButtonsArchadia.Olympiad_Back_Over\" fore=\"OlympiadButtonsArchadia.Olympiad_Back\"></td></tr></table></center></body></html>";
		m_Lock.Enter();
		if(m_PagesOly118.size() > 0 && page < m_PagesOly118.size())
		{
			html = m_PagesOly118[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"oly_118.htm", html.c_str(), 0);
	}
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly88(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly88.begin(); it != m_DBOly88.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly88.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly88.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly89(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly89.begin(); it != m_DBOly89.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly89.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly89.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly90(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly90.begin(); it != m_DBOly90.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly90.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly90.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly91(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly91.begin(); it != m_DBOly91.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly91.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly91.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly92(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly92.begin(); it != m_DBOly92.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly92.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly92.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly93(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly93.begin(); it != m_DBOly93.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly93.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly93.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly94(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly94.begin(); it != m_DBOly94.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly94.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly94.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly95(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly95.begin(); it != m_DBOly95.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly95.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly95.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly96(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly96.begin(); it != m_DBOly96.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly96.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly96.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly97(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly97.begin(); it != m_DBOly97.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly97.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly97.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly98(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly98.begin(); it != m_DBOly98.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly98.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly98.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly99(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly99.begin(); it != m_DBOly99.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly99.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly99.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly100(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly100.begin(); it != m_DBOly100.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly100.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly100.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly101(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly101.begin(); it != m_DBOly101.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly101.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly101.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly102(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly102.begin(); it != m_DBOly102.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly102.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly102.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly103(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly103.begin(); it != m_DBOly103.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly103.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly103.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly104(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly104.begin(); it != m_DBOly104.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly104.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly104.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly105(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly105.begin(); it != m_DBOly105.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly105.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly105.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly106(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly106.begin(); it != m_DBOly106.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly106.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly106.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly107(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly107.begin(); it != m_DBOly107.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly107.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly107.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly108(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly108.begin(); it != m_DBOly108.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly108.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly108.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly109(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly109.begin(); it != m_DBOly109.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly109.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly109.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly110(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly110.begin(); it != m_DBOly110.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly110.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly110.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly111(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly111.begin(); it != m_DBOly111.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly111.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly111.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly112(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly112.begin(); it != m_DBOly112.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly112.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly112.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly113(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly113.begin(); it != m_DBOly113.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly113.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly113.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly114(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly114.begin(); it != m_DBOly114.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly114.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly114.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly115(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly115.begin(); it != m_DBOly115.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly115.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly115.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly116(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly116.begin(); it != m_DBOly116.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly116.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly116.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly117(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly117.begin(); it != m_DBOly117.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly117.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly117.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void COlympiadStatusPages::OnDBLoadOly118(wstring name, INT32 match_count, INT32 win_count, INT32 olympiad_lose_count, INT32 olympiad_point)
{
	guard;

	OlympiadUserInfo pui;
	pui.name = name;
	pui.match_count = match_count;
	pui.win_count = win_count;
	pui.olympiad_lose_count = olympiad_lose_count;
	pui.olympiad_point = olympiad_point;

	bool done = false;
	m_Lock.Enter();
	for(vector<OlympiadUserInfo>::iterator it = m_DBOly118.begin(); it != m_DBOly118.end();it++)
	{
		if(it->olympiad_point < olympiad_point)
		{
			m_DBOly118.insert(it, pui);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_DBOly118.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}


void COlympiadStatusPages::TimerExpired()
{
	guard;
	if(m_Enabled)
	{
		//BETA
		/*if(m_RefreshOlyRunning && !COlympiadSystem::GetOlympiadStatus())
		{
			unguard;
			return;
		}*/

		if (m_LoadCustom)
		{
			time_t currentTime = time(0);
			if(m_RefreshTime < currentTime)
			{
				m_LoadCustom = false;
				UINT pagesOly88 = 0, pagesOly89 = 0;
				UINT pagesOly90 = 0, pagesOly91 = 0;
				UINT pagesOly92 = 0, pagesOly93 = 0;
				UINT pagesOly94 = 0, pagesOly95 = 0;
				UINT pagesOly96 = 0, pagesOly97 = 0;
				UINT pagesOly98 = 0, pagesOly99 = 0;
				UINT pagesOly100 = 0, pagesOly101 = 0;
				UINT pagesOly102 = 0, pagesOly103 = 0;
				UINT pagesOly104 = 0, pagesOly105 = 0;
				UINT pagesOly106 = 0, pagesOly107 = 0;
				UINT pagesOly108 = 0, pagesOly109 = 0;
				UINT pagesOly110 = 0, pagesOly111 = 0;
				UINT pagesOly112 = 0, pagesOly113 = 0;
				UINT pagesOly114 = 0, pagesOly115 = 0;
				UINT pagesOly116 = 0, pagesOly117 = 0;
				UINT pagesOly118 = 0;
				m_Lock.Enter();

				GeneratePagesOly88();
				GeneratePagesOly89();
				GeneratePagesOly90();
				GeneratePagesOly91();
				GeneratePagesOly92();
				GeneratePagesOly93();
				GeneratePagesOly94();
				GeneratePagesOly95();
				GeneratePagesOly96();
				GeneratePagesOly97();
				GeneratePagesOly98();
				GeneratePagesOly99();
				GeneratePagesOly100();
				GeneratePagesOly101();
				GeneratePagesOly102();
				GeneratePagesOly103();
				GeneratePagesOly104();
				GeneratePagesOly105();
				GeneratePagesOly106();
				GeneratePagesOly107();
				GeneratePagesOly108();
				GeneratePagesOly109();
				GeneratePagesOly110();
				GeneratePagesOly111();
				GeneratePagesOly112();
				GeneratePagesOly113();
				GeneratePagesOly114();
				GeneratePagesOly115();
				GeneratePagesOly116();
				GeneratePagesOly117();
				GeneratePagesOly118();

				m_DBOly88.clear();
				m_DBOly89.clear();
				m_DBOly90.clear();
				m_DBOly91.clear();
				m_DBOly92.clear();
				m_DBOly93.clear();
				m_DBOly94.clear();
				m_DBOly95.clear();
				m_DBOly96.clear();
				m_DBOly97.clear();
				m_DBOly98.clear();
				m_DBOly99.clear();
				m_DBOly100.clear();
				m_DBOly101.clear();
				m_DBOly102.clear();
				m_DBOly103.clear();
				m_DBOly104.clear();
				m_DBOly105.clear();
				m_DBOly106.clear();
				m_DBOly107.clear();
				m_DBOly108.clear();
				m_DBOly109.clear();
				m_DBOly110.clear();
				m_DBOly111.clear();
				m_DBOly112.clear();
				m_DBOly113.clear();
				m_DBOly114.clear();
				m_DBOly115.clear();
				m_DBOly116.clear();
				m_DBOly117.clear();
				m_DBOly118.clear();
				pagesOly88 = static_cast<UINT>(m_PagesOly88.size());
				pagesOly89 = static_cast<UINT>(m_PagesOly89.size());
				pagesOly90 = static_cast<UINT>(m_PagesOly90.size());
				pagesOly91 = static_cast<UINT>(m_PagesOly91.size());
				pagesOly92 = static_cast<UINT>(m_PagesOly92.size());
				pagesOly93 = static_cast<UINT>(m_PagesOly93.size());
				pagesOly94 = static_cast<UINT>(m_PagesOly94.size());
				pagesOly95 = static_cast<UINT>(m_PagesOly95.size());
				pagesOly96 = static_cast<UINT>(m_PagesOly96.size());
				pagesOly97 = static_cast<UINT>(m_PagesOly97.size());
				pagesOly98 = static_cast<UINT>(m_PagesOly98.size());
				pagesOly99 = static_cast<UINT>(m_PagesOly99.size());
				pagesOly100 = static_cast<UINT>(m_PagesOly100.size());
				pagesOly101 = static_cast<UINT>(m_PagesOly101.size());
				pagesOly102 = static_cast<UINT>(m_PagesOly102.size());
				pagesOly103 = static_cast<UINT>(m_PagesOly103.size());
				pagesOly104 = static_cast<UINT>(m_PagesOly104.size());
				pagesOly105 = static_cast<UINT>(m_PagesOly105.size());
				pagesOly106 = static_cast<UINT>(m_PagesOly106.size());
				pagesOly107 = static_cast<UINT>(m_PagesOly107.size());
				pagesOly108 = static_cast<UINT>(m_PagesOly108.size());
				pagesOly109 = static_cast<UINT>(m_PagesOly109.size());
				pagesOly110 = static_cast<UINT>(m_PagesOly110.size());
				pagesOly111 = static_cast<UINT>(m_PagesOly111.size());
				pagesOly112 = static_cast<UINT>(m_PagesOly112.size());
				pagesOly113 = static_cast<UINT>(m_PagesOly113.size());
				pagesOly114 = static_cast<UINT>(m_PagesOly114.size());
				pagesOly115 = static_cast<UINT>(m_PagesOly115.size());
				pagesOly116 = static_cast<UINT>(m_PagesOly116.size());
				pagesOly117 = static_cast<UINT>(m_PagesOly117.size());
				pagesOly118 = static_cast<UINT>(m_PagesOly118.size());
				m_Lock.Leave();

				g_DB.RequestLoadOlympiad88();
				g_DB.RequestLoadOlympiad89();
				g_DB.RequestLoadOlympiad90();
				g_DB.RequestLoadOlympiad91();
				g_DB.RequestLoadOlympiad92();
				g_DB.RequestLoadOlympiad93();
				g_DB.RequestLoadOlympiad94();
				g_DB.RequestLoadOlympiad95();
				g_DB.RequestLoadOlympiad96();
				g_DB.RequestLoadOlympiad97();
				g_DB.RequestLoadOlympiad98();
				g_DB.RequestLoadOlympiad99();
				g_DB.RequestLoadOlympiad100();
				g_DB.RequestLoadOlympiad101();
				g_DB.RequestLoadOlympiad102();
				g_DB.RequestLoadOlympiad103();
				g_DB.RequestLoadOlympiad104();
				g_DB.RequestLoadOlympiad105();
				g_DB.RequestLoadOlympiad106();
				g_DB.RequestLoadOlympiad107();
				g_DB.RequestLoadOlympiad108();
				g_DB.RequestLoadOlympiad109();
				g_DB.RequestLoadOlympiad110();
				g_DB.RequestLoadOlympiad111();
				g_DB.RequestLoadOlympiad112();
				g_DB.RequestLoadOlympiad113();
				g_DB.RequestLoadOlympiad114();
				g_DB.RequestLoadOlympiad115();
				g_DB.RequestLoadOlympiad116();
				g_DB.RequestLoadOlympiad117();
				g_DB.RequestLoadOlympiad118();
				m_RefreshTime = time(0) + m_RefreshTimeout;

	//			g_Log.Add(CLog::Blue, "[%s] Refreshing status - generated C88[%d] C89[%d] C90[%d] C91[%d] C92[%d] C93[%d] C94[%d] C95[%d] C96[%d] C97[%d] C98[%d] C99[%d] C100[%d] C101[%d] C102[%d] C103[%d] C104[%d] C105[%d] C106[%d] C107[%d] C108[%d] C109[%d] C110[%d] C111[%d] C112[%d] C113[%d] C114[%d] C115[%d] C116[%d] C117[%d] C118[%d] page(s).", __FUNCTION__, pagesOly88, pagesOly89, pagesOly90, pagesOly91, pagesOly92, pagesOly93, pagesOly94, pagesOly95, pagesOly96, pagesOly97, pagesOly98, pagesOly99, pagesOly100, pagesOly101, pagesOly102, pagesOly103, pagesOly104, pagesOly105, pagesOly106, pagesOly107, pagesOly108, pagesOly109, pagesOly110, pagesOly111, pagesOly112, pagesOly113, pagesOly114, pagesOly115, pagesOly116, pagesOly117, pagesOly118);
			}
		}
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly88()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_88.htm");
	if(wHTML)
	{
		if(m_DBOly88.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly88.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly88.size() / 15);
			if((m_DBOly88.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly88.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly88[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly88.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly88.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_88.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly89()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_89.htm");
	if(wHTML)
	{
		if(m_DBOly89.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly89.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly89.size() / 15);
			if((m_DBOly89.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly89.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly89[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly89.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly89.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_89.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly90()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_90.htm");
	if(wHTML)
	{
		if(m_DBOly90.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly90.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly90.size() / 15);
			if((m_DBOly90.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly90.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly90[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly90.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly90.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_90.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly91()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_91.htm");
	if(wHTML)
	{
		if(m_DBOly91.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly91.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly91.size() / 15);
			if((m_DBOly91.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly91.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly91[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly91.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly91.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_91.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly92()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_92.htm");
	if(wHTML)
	{
		if(m_DBOly92.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly92.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly92.size() / 15);
			if((m_DBOly92.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly92.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly92[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly92.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly92.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_92.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly93()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_93.htm");
	if(wHTML)
	{
		if(m_DBOly93.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly93.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly93.size() / 15);
			if((m_DBOly93.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly93.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly93[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly93.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly93.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_93.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly94()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_94.htm");
	if(wHTML)
	{
		if(m_DBOly94.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly94.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly94.size() / 15);
			if((m_DBOly94.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly94.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly94[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly94.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly94.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_94.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly95()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_95.htm");
	if(wHTML)
	{
		if(m_DBOly95.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly95.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly95.size() / 15);
			if((m_DBOly95.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly95.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly95[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly95.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly95.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_95.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly96()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_96.htm");
	if(wHTML)
	{
		if(m_DBOly96.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly96.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly96.size() / 15);
			if((m_DBOly96.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly96.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly96[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly96.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly96.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_96.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly97()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_97.htm");
	if(wHTML)
	{
		if(m_DBOly97.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly97.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly97.size() / 15);
			if((m_DBOly97.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly97.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly97[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly97.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly97.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_97.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly98()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_98.htm");
	if(wHTML)
	{
		if(m_DBOly98.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly98.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly98.size() / 15);
			if((m_DBOly98.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly98.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly98[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly98.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly98.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_98.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly99()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_99.htm");
	if(wHTML)
	{
		if(m_DBOly99.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly99.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly99.size() / 15);
			if((m_DBOly99.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly99.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly99[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly99.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly99.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_99.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly100()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_100.htm");
	if(wHTML)
	{
		if(m_DBOly100.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly100.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly100.size() / 15);
			if((m_DBOly100.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly100.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly100[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly100.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly100.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_100.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly101()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_101.htm");
	if(wHTML)
	{
		if(m_DBOly101.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly101.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly101.size() / 15);
			if((m_DBOly101.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly101.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly101[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly101.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly101.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_101.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly102()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_102.htm");
	if(wHTML)
	{
		if(m_DBOly102.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly102.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly102.size() / 15);
			if((m_DBOly102.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly102.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly102[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly102.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly102.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_102.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly103()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_103.htm");
	if(wHTML)
	{
		if(m_DBOly103.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly103.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly103.size() / 15);
			if((m_DBOly103.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly103.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly103[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly103.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly103.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_103.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly104()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_104.htm");
	if(wHTML)
	{
		if(m_DBOly104.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly104.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly104.size() / 15);
			if((m_DBOly104.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly104.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly104[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly104.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly104.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_104.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly105()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_105.htm");
	if(wHTML)
	{
		if(m_DBOly105.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly105.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly105.size() / 15);
			if((m_DBOly105.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly105.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly105[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly105.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly105.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_105.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly106()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_106.htm");
	if(wHTML)
	{
		if(m_DBOly106.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly106.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly106.size() / 15);
			if((m_DBOly106.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly106.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly106[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly106.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly106.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_106.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly107()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_107.htm");
	if(wHTML)
	{
		if(m_DBOly107.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly107.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly107.size() / 15);
			if((m_DBOly107.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly107.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly107[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly107.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly107.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_107.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly108()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_108.htm");
	if(wHTML)
	{
		if(m_DBOly108.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly108.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly108.size() / 15);
			if((m_DBOly108.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly108.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly108[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly108.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly108.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_108.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly109()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_109.htm");
	if(wHTML)
	{
		if(m_DBOly109.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly109.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly109.size() / 15);
			if((m_DBOly109.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly109.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly109[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly109.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly109.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_109.htm !", __FUNCTION__);
	}
	unguard;
}


void COlympiadStatusPages::GeneratePagesOly110()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_110.htm");
	if(wHTML)
	{
		if(m_DBOly110.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly110.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly110.size() / 15);
			if((m_DBOly110.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly110.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly110[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly110.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly110.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_110.htm !", __FUNCTION__);
	}
	unguard;
}


void COlympiadStatusPages::GeneratePagesOly111()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_111.htm");
	if(wHTML)
	{
		if(m_DBOly111.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly111.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly111.size() / 15);
			if((m_DBOly111.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly111.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly111[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly111.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly111.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_111.htm !", __FUNCTION__);
	}
	unguard;
}


void COlympiadStatusPages::GeneratePagesOly112()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_112.htm");
	if(wHTML)
	{
		if(m_DBOly112.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly112.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly112.size() / 15);
			if((m_DBOly112.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly112.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly112[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly112.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly112.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_112.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly113()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_113.htm");
	if(wHTML)
	{
		if(m_DBOly113.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly113.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly113.size() / 15);
			if((m_DBOly113.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly113.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly113[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly113.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly113.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_113.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly114()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_114.htm");
	if(wHTML)
	{
		if(m_DBOly114.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly114.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly114.size() / 15);
			if((m_DBOly114.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly114.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly114[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly114.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly114.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_114.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly115()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_115.htm");
	if(wHTML)
	{
		if(m_DBOly115.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly115.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly115.size() / 15);
			if((m_DBOly115.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly115.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly115[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly115.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly115.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_115.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly116()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_116.htm");
	if(wHTML)
	{
		if(m_DBOly116.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly116.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly116.size() / 15);
			if((m_DBOly116.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly116.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly116[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly116.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly116.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_116.htm !", __FUNCTION__);
	}
	unguard;
}

void COlympiadStatusPages::GeneratePagesOly117()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_117.htm");
	if(wHTML)
	{
		if(m_DBOly117.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly117.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly117.size() / 15);
			if((m_DBOly117.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly117.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly117[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly117.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly117.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_117.htm !", __FUNCTION__);
	}
	unguard;
}


void COlympiadStatusPages::GeneratePagesOly118()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"oly_118.htm");
	if(wHTML)
	{
		if(m_DBOly118.size() > 0)
		{
			wstring html(wHTML);
			m_PagesOly118.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBOly118.size() / 15);
			if((m_DBOly118.size() % 15) != 0)
			{
				totalPages++;
			}
			WCHAR temp[8190] = { 0 };
			size_t startPos = html.find(L"<template_line>");
			wstring templateLine, templateLineEx;
			if(startPos != wstring::npos)
			{
				size_t endPos = html.find(L"</template_line>", startPos);
				if(endPos != wstring::npos)
				{
					templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
					templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

					//<template_line><tr><td width="160"><?boss_name?></td><td width="50"><?boss_status?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					UINT place = 0;
					for(UINT n=0;n<m_DBOly118.size();n++)
					{
						OlympiadUserInfo& pui = m_DBOly118[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);
						line = Utils::ReplaceString(line, L"<?p_matchcount?>", pui.match_count, true);
						line = Utils::ReplaceString(line, L"<?p_win_count?>", pui.win_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_lose_count?>", pui.olympiad_lose_count, true);
						line = Utils::ReplaceString(line, L"<?p_oly_point?>", pui.olympiad_point, true);

						linesStream << line << endl;
						counter++;
						if((counter%15) == 0)
						{
							wstring templ = html;
							_itow(page+1, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
							_itow(totalPages, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
							UINT prevPage = 0;
							if(page > 0)
							{
								prevPage = page - 1;
							}
							_itow(prevPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
							UINT nextPage = 0;
							if(totalPages > 1)
							{
								if((page+1) < totalPages)
								{
									nextPage = page + 1;
								}
							}
							_itow(nextPage, temp, 10);
							templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
							templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
							m_PagesOly118.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
						}
					}
					if(pageFlag)
					{
						//add last page
						wstring templ = html;
						_itow(page+1, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?page?>", temp, true);
						_itow(totalPages, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?total_pages?>", temp, true);
						UINT prevPage = 0;
						if(page > 0)
						{
							prevPage = page - 1;
						}
						_itow(prevPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?previous_page?>", temp, true);
						UINT nextPage = 0;
						if(totalPages > 1)
						{
							if((page+1) < totalPages)
							{
								nextPage = page + 1;
							}
						}
						_itow(nextPage, temp, 10);
						templ = Utils::ReplaceString(templ, L"<?next_page?>", temp, true);
						templ = Utils::ReplaceString(templ, templateLineEx, linesStream.str(), true);
						m_PagesOly118.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - oly_118.htm !", __FUNCTION__);
	}
	unguard;
}
