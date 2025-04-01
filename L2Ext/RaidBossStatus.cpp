#include "stdafx.h"
#include "RaidBossStatus.h"
#include "NpcDb.h"
#include "DB.h"
#include "HtmlCache.h"
#include "PlayerAction.h"

CRaidBossStatus g_RaidBossStatus;

void CRaidBossStatus::Init()
{
	LoadINI();
	if(m_Enabled)
	{
		g_Log.Add(CLog::Blue, "[%s] Feature is enabled, refresh timeout [%d] second(s), loaded [%d] DB name(s).", __FUNCTION__, m_RefreshTimeout, m_DBNames.size());
		m_RefreshTime = time(0) + m_RefreshTimeout;
		g_DB.RequestLoadRaidBossStatus();
	}
}

/*
[RaidBossStatus]
;Enables new bypass: "bypass -h rb_status?page=0" - will show raidboss status
Enabled=0
;Refresh time - how often it will refresh the status
RefreshTimeout=60

*/

void CRaidBossStatus::LoadINI()
{
	CTL;

	const TCHAR* section = _T("RaidBossStatus");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);
	m_IsGold = GetPrivateProfileInt(section, _T("GoldType"), 0, g_ConfigFile);
	m_RefreshTimeout = GetPrivateProfileInt(section, _T("RefreshTimeout"), 0, g_ConfigFile);
	TCHAR temp[0x10000] = { 0 };
	//Not used finally
	//RaidbossDBNameList={flame_stone_golem;1025524} {krokian_padisha_sobekk;1025202} {faf_herald_lokness;1025198} {wdragon_priest_sheshark;1025199} {degeneration_golem;1025523} {domb_death_cabrio;1025035} {golkonda_longhorn;1025126} {hallate_the_death_lord;1025220} {kernon;1025054} {antaras_cloe;1025109} {beastlord_behemoth;1025269} {bloody_empress_decarbia;1025266} {bloody_tree_vermilion;1025249} {cherub_garacsia;1025450} {demonic_agent_falston;1025322} {gargoyle_lord_tiphon;1025255} {geyser_guardian_hestia;1025293} {ipos_the_death_lord;1025276} {ketra_chief_brakki;1025305} {ketra_commander_tayr;1025302} {ketra_hero_hekaton;1025299} {last_lesser_glaki;1025245} {last_lesser_olkuth;1025244} {palibati_queen_themis;1025252} {raid_boss_von_helman;1025328} {shuriel_fire_of_wrath;1025143} {storm_winged_naga;1025229} {vanor_chief_kandra;1025235} {varka_chief_horuth;1025315} {varka_commnder_mos;1025312} {varka_hero_shadith;1025309} {anakim;1025286} {lilith;1025283}
	//This is the correct
	//valakas follower_frintessa flame_stone_golem krokian_padisha_sobekk faf_herald_lokness wdragon_priest_sheshark degeneration_golem antaras baium zaken orfen core queen_ant domb_death_cabrio domb_death_cabrio1 domb_death_cabrio2 golkonda_longhorn golkonda_longhorn1 golkonda_longhorn2 hallate_the_death_lord hallate_the_death_lord1 hallate_the_death_lord2 kernon kernon1 kernon2 antaras_cloe beastlord_behemoth bloody_empress_decarbia bloody_tree_vermilion cherub_garacsia demonic_agent_falston gargoyle_lord_tiphon geyser_guardian_hestia ipos_the_death_lord ketra_chief_brakki ketra_commander_tayr ketra_hero_hekaton last_lesser_glaki last_lesser_olkuth palibati_queen_themis raid_boss_von_helman shuriel_fire_of_wrath storm_winged_naga vanor_chief_kandra varka_chief_horuth varka_commnder_mos varka_hero_shadith anakim lilith blinding_fire_barakiel
	if(GetPrivateProfileString(section, _T("RaidbossDBNameList"), 0, temp, 0x10000, g_ConfigFile))
	{
		wstringstream nameStream(temp);
		wstring rbName;
		//UINT classID = 0;
		while(nameStream >> rbName /*>> classID*/)
		{
			m_DBNames.push_back(rbName);
			//m_DBNames[rbName] = classID;
		}
	}
	//StaticRespawnBosses={amber;86400} {antaras;406400}
	if(GetPrivateProfileString(section, _T("StaticRespawnBosses"), 0, temp, 0x10000, g_ConfigFile))
	{
		wstring params = Parser::Replace(temp, L'{', L' ');
		params = Parser::Replace(params, L'}', L' ');
		params = Parser::Replace(params, L';', L' ');
		wstringstream paramStream(params);
		wstring rbName;
		UINT respawnTime = 0;
		while(paramStream >> rbName >> respawnTime)
		{
		//	g_Log.Add(CLog::Blue, "[%s] name[%S] respawn[%d]", __FUNCTION__, rbName.c_str(), respawnTime);
			m_StaticDB[rbName] = respawnTime;
		}
	}
	if(GetPrivateProfileString(section, _T("RespawnAnnounce"), 0, temp, 0x10000, g_ConfigFile))
	{
		vector<wstring> params = Parser::Split(temp, L";{}");
		//{boss_name;time_in_seconds_before_respawn;Announce message}{boss_name2;time_in_seconds_before_respawn;Announce message2}
		vector<wstring> rparams;
		for(UINT n=0;n<params.size();n++)
		{
			wstring param = Parser::Trim(params[n]);
			if(param.size() > 0)
				rparams.push_back(params[n]);
		}

		RaidBossRespawnAnnounce ra;
		INT32 paramIdx = 1;
		for(UINT n=0;n<rparams.size();n++)
		{
			wstring param = rparams[n];
			switch(paramIdx)
			{
			case 4:
				{
					paramIdx = 1;
				}
			case 1:
				{
					ra.npcName = param;
					break;
				}
			case 2:
				{
					ra.announceTime = _wtoi(param.c_str());
					break;
				}
			case 3:
				{
					ra.message = param;
					m_Announce[ra.npcName] = ra;
					break;
				}

			}
			paramIdx++;
		}
	}

	if(GetPrivateProfileString(section, _T("AliveColor"), 0, temp, 16384, g_ConfigFile))
	{
		m_AliveColor = temp;
	}
	if(GetPrivateProfileString(section, _T("DeadColor"), 0, temp, 16384, g_ConfigFile))
	{
		m_DeadColor = temp;
	}
	if(m_AliveColor.size() == 0)
	{
		m_AliveColor = L"69ED74";
	}
	if(m_DeadColor.size() == 0)
	{
		m_DeadColor = L"854CA6";
	}

	//m_IsRunning = false;
}

UINT CRaidBossStatus::GetStaticRespawn(wstring name)
{
	guard;
	UINT respawn = 0;

	map<wstring, UINT>::iterator it = m_StaticDB.find(name);
	if(it!=m_StaticDB.end())
	{
		respawn = it->second;
	}

	unguard;
	return respawn;
}

UINT CRaidBossStatus::GetDeathTime(wstring name)
{
	CTL;
	{
		AUTO_LOCK(m_Lock);
		map<wstring, RaidBossInfo>::iterator it = m_DB.find(name);
		if(it != m_DB.end())
		{
			if(it->second.alive == false)
			{
				return it->second.deathTime;
			}
		}
	}

	return 0;
}

void CRaidBossStatus::OnDBLoad(wstring name, int x, int y, int z, bool alive, UINT deathTime)
{
	guard;

	bool canBeAdded = false;
	for(UINT n=0;n<m_DBNames.size();n++)
	{
		if(name == m_DBNames[n])
		{
			canBeAdded = true;
			break;
		}
	}
	if(canBeAdded)
	{
		RaidBossInfo rbi;
		rbi.alive = alive;
		rbi.deathTime = deathTime;
		rbi.dbName = name;
		rbi.name = g_NpcDb.GetClientNameByName(name);
		if(rbi.name.size() == 0)
		{
			rbi.name = name;
		}
		rbi.pos.x = x;
		rbi.pos.y = y;
		rbi.pos.z = z;

		m_Lock.Enter();
		
		map<wstring, RaidBossInfo>::iterator Iter = m_DB.find(name);
		if(Iter!=m_DB.end())
		{
			Iter->second = rbi;
		}
		else
		{
			//m_DB[rbi.dbName] = rbi;
			m_DB.insert(pair<wstring, RaidBossInfo>(rbi.dbName,rbi) );
		}

		m_Lock.Leave();
	}
	unguard;
}

void CRaidBossStatus::OnNpcDie(CNPC *pNPC)
{
	guard;
	if(pNPC->ValidCreature())
	{
		OnDBLoad(g_NpcDb.GetDbNameByClassId(pNPC->pSD->nNpcClassID), 0, 0, 0, false, time(0));
	}
	else
		g_Log.Add(CLog::Error, "[%s] Cannot Find Valid NPC Death! Please report to Dev!", __FUNCTION__);

	unguard;
}

void CRaidBossStatus::OnNpcSpawn(CNPC *pNPC)
{
	guard;
	if(pNPC->ValidCreature())
	{
		OnDBLoad(g_NpcDb.GetDbNameByClassId(pNPC->pSD->nNpcClassID), 0, 0, 0, true, time(0));
	}
	else
		g_Log.Add(CLog::Error, "[%s] Cannot Find Valid NPC Alive! Please report to Dev!", __FUNCTION__);

	unguard;
}

void CRaidBossStatus::TimerExpired()
{
	guard;
	if(m_Enabled)
	{
		time_t currentTime = time(0);
		if(m_RefreshTime < currentTime)
		{
			m_Lock.Enter();
			UINT pages = 0;
			GeneratePages();
			//m_DB.clear();
			pages = static_cast<UINT>(m_Pages.size());
			m_Lock.Leave();
			/*{
				AUTO_LOCK(m_Lock);
				//Generate pages
				GeneratePages();
				m_DB.clear();
				pages = static_cast<UINT>(m_Pages.size());
			}*/

			//g_DB.RequestLoadRaidBossStatus();
			m_RefreshTime = time(0) + m_RefreshTimeout;
			
//			g_Log.Add(CLog::Blue, "[%s] Refreshing status - generated [%d] page(s).", __FUNCTION__, pages);
		}

		//handle announces
		for(map<wstring, RaidBossRespawnAnnounce>::iterator it = m_Announce.begin(); it != m_Announce.end(); it++)
		{
			if(UINT deathTime = GetDeathTime(it->first))
			{
				if(UINT staticRespawn = GetStaticRespawn(it->first))
				{
					UINT spawnTime = deathTime + staticRespawn;
					spawnTime -= it->second.announceTime;
			//		g_Log.Add(CLog::Blue, "[%s] spawn[%d] vs current[%d] - npc[%S]", __FUNCTION__, spawnTime, currentTime, it->first.c_str());
					if(spawnTime == currentTime)
					{
						Utils::BroadcastToAllUser_Announce(it->second.message.c_str());
					}
				}
			}
		}
	}
	unguard;
}

wstring CRaidBossStatus::CheckNames(wstring name)
{
	//Normal
	/*if( name == L"Shilen's Messenger Cabrio" )
	{
		return L"Shilen Messenger Cabrio (FG)";				
	}

	if( name == L"Kernon" )
	{
		return L"Kernon (TOI)";
	}

	if( name == L"Longhorn Golkonda" )
	{
		return L"Longhorn Golkonda (TOI)";
	}
	
	if( name == L"Death Lord Hallate" )
	{
		return L"Death Lord Hallate (TOI)";
	}

	//EF
	if( name == L"domb_death_cabrio1" )
	{
		return L"Shilen Messenger Cabrio (EF)";				
	}

	if( name == L"kernon1" )
	{
		return L"Kernon (EF)";
	}

	if( name == L"golkonda_longhorn1" )
	{
		return L"Longhorn Golkonda (EF)";
	}
	
	if( name == L"hallate_the_death_lord1" )
	{
		return L"Death Lord Hallate (EF)";
	}

	//GC
	if( name == L"domb_death_cabrio2" )
	{
		return L"Shilen Messenger Cabrio (GC)";				
	}

	if( name == L"kernon2" )
	{
		return L"Kernon (GC)";
	}

	if( name == L"golkonda_longhorn2" )
	{
		return L"Longhorn Golkonda (GC)";
	}
	
	if( name == L"hallate_the_death_lord2" )
	{
		return L"Death Lord Hallate (GC)";
	}*/

	return name;
}

void CRaidBossStatus::GeneratePages()
{
	guard;
	const WCHAR* wHTML = g_HtmlCache.Get(L"rb_status.htm");
	if(wHTML)
	{
		if(m_DB.size() > 0)
		{
			wstring html(wHTML);
			m_Pages.clear();
			UINT page = 0;
			UINT totalPages = static_cast<UINT>(m_DB.size() / 15);
			if((m_DB.size() % 15) != 0)
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

					//<template_line><tr><td width="150"><?boss_name?></td><td width="50"><?boss_status?></td><td width="50"><?boss_death?></td></tr></template_line>	
					wstringstream linesStream;
					bool pageFlag = true;
					UINT counter = 0;
					for(map<wstring, RaidBossInfo>::iterator it = m_DB.begin(); it != m_DB.end(); it++)
					{
						pageFlag = true;
						wstring line = templateLine;


						if(it->second.alive)
						{
							wstring color;
							color = L"<font color=\"";
							color += m_AliveColor;
							color += L"\">Alive</font>";
							line = Utils::ReplaceString(line, L"<?boss_status?>", color, true);
							line = Utils::ReplaceString(line, L"<?boss_death?>", L" - ", true);

							//BETA
							wstring boss_name;
							boss_name = L"<font color=\"";
							boss_name += m_AliveColor;
							boss_name += L"\">";
							//boss_name += it->second.name;
							if(m_IsGold)
								boss_name += CheckNames(it->second.name);
							else
								boss_name += it->second.name;
							boss_name += L"</font>";

							line = Utils::ReplaceString(line, L"<?boss_name?>", boss_name, true);

						}else
						{
							wstringstream deathTimeStream;
							UINT staticRespawn = GetStaticRespawn(it->second.dbName);
							if(staticRespawn > 0)
							{
								UINT currentTime = time(0);
								UINT respawnTimeout = it->second.deathTime + staticRespawn;
								int spawnTime = respawnTimeout - currentTime;
								if(spawnTime > 0)
								{
									int seconds = spawnTime % 60;
									spawnTime /= 60;
									int minutes = spawnTime % 60;
									spawnTime /= 60;
									int hours = spawnTime % 24;
									spawnTime /= 24;
									int days = spawnTime;
									
									if(days > 0)
										deathTimeStream << days << L":";
									if(hours > 9)
										deathTimeStream << hours << L":";
									else
										deathTimeStream << L"0" << hours << L":";
									if(minutes > 9)
										deathTimeStream << minutes << L":";
									else
										deathTimeStream << L"0" << minutes << L":";
									if(seconds > 9)
										deathTimeStream << seconds;
									else
										deathTimeStream << L"0" << seconds;

								}else
								{
									deathTimeStream << L"00:00:00";
								}
							}else
							{
								tm ti;
								GetTimeInfo(ti, it->second.deathTime);
								deathTimeStream << 1900 + ti.tm_year << L"/" << (ti.tm_mon+1) << L"/" << ti.tm_mday << L" " << ti.tm_hour << L":" << ti.tm_min << L":" << ti.tm_sec;
							}
							wstring color;
							color = L"<font color=\"";
							color += m_DeadColor;
							color += L"\">Dead</font>";
							line = Utils::ReplaceString(line, L"<?boss_status?>", color, true);
							line = Utils::ReplaceString(line, L"<?boss_death?>", deathTimeStream.str(), true);

							//BETA
							wstring boss_name;
							boss_name = L"<font color=\"";
							boss_name += m_DeadColor;
							boss_name += L"\">";
							//boss_name += it->second.name;
							if(m_IsGold)
								boss_name += CheckNames(it->second.name);
							else
								boss_name += it->second.name;
							boss_name += L"</font>";

							line = Utils::ReplaceString(line, L"<?boss_name?>", boss_name, true);
						}
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
		g_Log.Add(CLog::Error, "[%s] Cannot find html - rb_status.htm !", __FUNCTION__);
	}
	unguard;
}

void CRaidBossStatus::RequestRaidBossStatus(User *pUser, UINT page)
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

		PlayerAction::ShowHTML(pUser, L"rb_status.htm", html.c_str(), 0);
	}
	unguard;
}