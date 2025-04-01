#include "stdafx.h"
#include "ClanReputationRank.h"
#include "DB.h"
#include "HtmlCache.h"
#include "PlayerAction.h"

CClanReputationRank g_ClanReputationRank;

void CClanReputationRank::Init()
{
	m_ResetTime = 0;
	m_ResetDone = false;

	LoadINI();
	if(m_Enabled)
	{
		g_Log.Add(CLog::Blue, "[%s] Feature is enabled, refresh timeout [%d] second(s).", __FUNCTION__, m_RefreshTimeout);
		m_RefreshTime = time(0) + m_RefreshTimeout;
		g_DB.RequestLoadClanRaidStatus(m_TopLimit);
	}
}

/*
[CClanReputationRank]
;Enables new bypass: "bypass -h rb_status?page=0" - will show raidboss status
Enabled=0
;Refresh time - how often it will refresh the status
RefreshTimeout=60
;Day Of Week which counter reset (0-Sunday / 1-Monday / 2-Tuesday / 3-wedsday / 4-thursday / 5-friday / 6-saturday)
ResetDay=0
ResetHour=0
ResetMinute=0
;Prize For First Place
PrizeId=0
PrizeQuanity=0
*/

void CClanReputationRank::LoadINI()
{
	const TCHAR* section = _T("CClanReputationRank");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);
	m_RefreshTimeout = GetPrivateProfileInt(section, _T("RefreshTimeout"), 0, g_ConfigFile);
	m_TopLimit = GetPrivateProfileInt(section, _T("TopLimit"), 200, g_ConfigFile);

	m_ResetDay = GetPrivateProfileInt(section, _T("ResetDay"), 0, g_ConfigFile);
	m_ResetHour = GetPrivateProfileInt(section, _T("ResetHour"), 0, g_ConfigFile);
	m_ResetMinute = GetPrivateProfileInt(section, _T("ResetMinute"), 0, g_ConfigFile);

	m_PrizeId = GetPrivateProfileInt(section, _T("PrizeId"), 0, g_ConfigFile);
	m_PrizeQuanity = GetPrivateProfileInt(section, _T("PrizeQuanity"), 0, g_ConfigFile);
}

void CClanReputationRank::RequestClanRaidStatus(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...</center></body></html>";
		m_Lock.Enter();
		if(m_Pages.size() > 0 && page < m_Pages.size())
		{
			html = m_Pages[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"clan_raid_status.htm", html.c_str(), 0);
	}
	unguard;
}

void CClanReputationRank::OnDBLoadPvP(UINT pledgeId, UINT raidCount, UINT raidRepCount, const WCHAR* wName)
{
	CTL;

	RaidStatusClan rsc;
	rsc.pledgeName = wName;
	rsc.pledgeId = pledgeId;
	rsc.raidCount = raidCount;
	rsc.raidRepCount = raidRepCount;

	bool done = false;
	m_Lock.Enter();
	for(StatusVector::iterator it = m_Status.begin(); it != m_Status.end();it++)
	{
		if(it->raidCount < raidCount)
		{
			m_Status.insert(it, rsc);
			done = true;
			break;
		}
	}
	if(!done)
	{
		m_Status.push_back(rsc);
	}
	m_Lock.Leave();
}

void CClanReputationRank::TimerExpired()
{
	CTL;
	if(m_Enabled)
	{
		time_t currentTime = time(0);
		tm ti;
		GetTimeInfo(ti);
		bool doit = true;

		
		if(ti.tm_wday == m_ResetDay)
		{
			if(ti.tm_hour == m_ResetHour)
			{
				if(ti.tm_min == m_ResetMinute)
				{
					if(!m_ResetDone)
					{
					
						//Send DB check for 3 leaders
						g_DB.RequestLoadClanRaidWinners();

						//
						m_ResetTime = time(0);
						m_ResetDone = true;

						doit = false;

						//save the list like sieges ?
					}

					if(m_ResetTime < (currentTime + 240) )
					{
						m_ResetTime = 0;
						m_ResetDone = false;
					}
				}
			}
		}

		if(doit)
		{
			if(m_RefreshTime < currentTime)
			{
				UINT pages = 0;
				m_Lock.Enter();
				//Generate pages
				GeneratePagesRaid();
				m_Status.clear();
				pages = static_cast<UINT>(m_Pages.size());
				m_Lock.Leave();

				g_DB.RequestLoadClanRaidStatus(m_TopLimit);
				m_RefreshTime = time(0) + m_RefreshTimeout;
				
//				g_Log.Add(CLog::Blue, "[%s] Refreshing status - generated [%d] page(s).", __FUNCTION__, pages);
			}
		}
	}
}

void CClanReputationRank::SetWinner(UINT nPlace, UINT pledgeId, UINT raidbosscount, UINT raidbossRepcount, wstring pledgeName, UINT leaderId, wstring leaderName)
{
	guard;

	if(	m_Enabled && m_PrizeId && m_PrizeQuanity )
	{
		if( nPlace == 0 )
		{
			g_DB.RequestItemDeliveryAdd(leaderId, m_PrizeId, m_PrizeQuanity, 0, 0);
		}
		else if( nPlace == 1)
		{

		}
		else if( nPlace == 2)
		{

		}
	}

	unguard;
}


void CClanReputationRank::GeneratePagesRaid()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"clan_raid_status.htm");
	if(wHTML)
	{
		if(m_Status.size() > 0)
		{
			wstring html(wHTML);
			m_Pages.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_Status.size() / 15);
			if((m_Status.size() % 15) != 0)
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
					for(UINT n=0;n<m_Status.size();n++)
					{
						RaidStatusClan& rsc = m_Status[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_place?>", place, true);
						line = Utils::ReplaceString(line, L"<?p_name?>", rsc.pledgeName, true);
						line = Utils::ReplaceString(line, L"<?p_raids?>", rsc.raidCount, true);
						line = Utils::ReplaceString(line, L"<?p_rep?>", rsc.raidRepCount, true);
						
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
							m_Pages.push_back(templ);
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
						m_Pages.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - clan_raid_status.htm !", __FUNCTION__);
	}
	unguard;
}