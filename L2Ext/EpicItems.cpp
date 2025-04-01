#include "StdAfx.h"
#include "EpicItems.h"
#include "DB.h"
#include "HtmlCache.h"
#include "PlayerAction.h"

CEpicItems g_EpicItems;

void CEpicItems::Init()
{
	m_Enabled = FALSE;

	LoadINI();
	if(m_Enabled)
	{
		g_Log.Add(CLog::Blue, "[%s] Feature is enabled, refresh timeout [%d] second(s).", __FUNCTION__, m_RefreshTimeout);
		m_RefreshTime = time(0) + m_RefreshTimeout;
		m_FirstTimeEpicItemsLoad = time(0) + 300; //First Time Run on Epic Items
		g_DB.RequestLoadEpicItems();
	}
}

/*
[EpicItems]
;Enables new bypass: "bypass -h rb_status?page=0" - will show Epic Item Status
Enabled=0
;Refresh time - how often it will refresh the status
RefreshTimeout=60
*/

void CEpicItems::LoadINI()
{
	const TCHAR* section = _T("EpicItems");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);
	m_RefreshTimeout = GetPrivateProfileInt(section, _T("RefreshTimeout"), 0, g_ConfigFile);
}

void CEpicItems::RequestEpicItems(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...</center></body></html>";
		m_Lock.Enter();
		if(m_PagesItems.size() > 0 && page < m_PagesItems.size())
		{
			html = m_PagesItems[page];
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"epic_items.htm", html.c_str(), 0);
	}
	unguard;
}

void CEpicItems::OnDBLoadEpicItems(wstring name, INT32 item_id)
{
	guard;

	EpicItems pui;
	pui.name = name;
	pui.item_id = item_id;

	bool done = false;
	m_Lock.Enter();
	for(vector<EpicItems>::iterator it = m_DBItems.begin(); it != m_DBItems.end();it++)
	{
		m_DBItems.insert(it, pui);
		done = true;
		break;
	}
	if(!done)
	{
		m_DBItems.push_back(pui);
	}
	m_Lock.Leave();
	unguard;
}

void CEpicItems::TimerExpired()
{
	guard;

	if(m_Enabled)
	{
		time_t currentTime = time(0);
		if(m_RefreshTime < currentTime)
		{
			UINT pagesItems = 0;

			m_Lock.Enter();
			GeneratePagesEpicItems();
			m_DBItems.clear();
			pagesItems = static_cast<UINT>(m_PagesItems.size());
			m_Lock.Leave();

			g_DB.RequestLoadEpicItems();
			m_RefreshTime = time(0) + m_RefreshTimeout;

//			g_Log.Add(CLog::Blue, "[%s] Refreshing Epic Items List - generated [%d] page(s).", __FUNCTION__, pagesItems );
		}

		if( (m_FirstTimeEpicItemsLoad < currentTime) && (m_FirstTimeEpicItemsLoad != 0) )
		{
			UINT pagesItems = 0;

			m_Lock.Enter();
			GeneratePagesEpicItems();
			m_DBItems.clear();
			pagesItems = static_cast<UINT>(m_PagesItems.size());
			m_Lock.Leave();

			g_DB.RequestLoadEpicItems();
			m_FirstTimeEpicItemsLoad = 0;

//			g_Log.Add(CLog::Blue, "[%s] Refreshing First Time Epic Items List - generated [%d] page(s).", __FUNCTION__, pagesItems );
		}
	}
	unguard;
}

void CEpicItems::GeneratePagesEpicItems()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"epic_items.htm");
	if(wHTML)
	{
		if(m_DBItems.size() > 0)
		{
			wstring html(wHTML);
			m_PagesItems.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DBItems.size() / 15);
			if((m_DBItems.size() % 15) != 0)
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
					for(UINT n=0;n<m_DBItems.size();n++)
					{
						EpicItems& pui = m_DBItems[n];
						pageFlag = true;
						wstring line = templateLine;
						place++;
						line = Utils::ReplaceString(line, L"<?p_name?>", pui.name, true);

						//INT32 itemid = pui.item_id;
						/*item_type = 6656 
						OR item_type = 6657 
						OR item_type = 6658 
						OR item_type = 6659 
						OR item_type = 6660 
						OR item_type = 6661 
						OR item_type = 6662 
						OR item_type = 8191*/

						wstring iconname = L"talk to gm about this";
						if( pui.item_id == 6656 ) {
							iconname = L"icon.accessory_earring_of_antaras_i00";
						}
						else if( pui.item_id == 6657) {
							iconname = L"icon.accessory_necklace_of_valakas_i00";
						}
						else if( pui.item_id == 6658) {
							iconname = L"icon.accessory_ring_of_baium_i00";
						}
						else if( pui.item_id == 6659) {
							iconname = L"icon.accessory_earring_of_zaken_i00";
						}
						else if( pui.item_id == 6660) {
							iconname = L"icon.accessory_ring_of_queen_ant_i00";
						}
						else if( pui.item_id == 6661) {
							iconname = L"icon.accessory_earring_of_orfen_i00";
						}
						else if( pui.item_id == 6662) {
							iconname = L"icon.accessory_ring_of_core_i00";
						}
						else if( pui.item_id == 8191) {
							iconname = L"icon.accessory_necklace_of_frintessa_i00";
						}
						line = Utils::ReplaceString(line, L"<?p_icon?>", iconname, true);
						
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
							m_PagesItems.push_back(templ);
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
						m_PagesItems.push_back(templ);
						linesStream.str(L"");
						pageFlag = false;
						page++;
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find html - epic_items.htm !", __FUNCTION__);
	}
	unguard;
}
