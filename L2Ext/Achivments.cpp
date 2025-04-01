#include "StdAfx.h"
#include "Achivments.h"
#include "ObjectDB.h"
#include "HTMLCacheManager.h"
#include "HtmlCache.h"
#include "PlayerAction.h"
#include "DB.h"

Achivments g_Achivments;

extern BOOL g_achiv;

struct AchivHWID
{
	INT32 AchivId;
	BYTE hwid[32];
	INT32 time;

		AchivHWID() : AchivId(0), time(0) {};
};

vector<AchivHWID> HWIDs;

void Achivments::LoadINI()
{
	guard;

	bool error = false;
	bool leerTest = false;
	int linea = 0;
	wstring filewTest = ReadFileW(L".//Achivements.ini");
	if(filewTest.size() > 0)
	{
		wstringstream filetest(filewTest);
		wstring lineTest;
		while(getline(filetest, lineTest))
		{
		//	g_Log.Add(CLog::Error, "name[%S]", line.c_str());
			linea++;
			if(lineTest.size() > 0)
			{
				
				if( lineTest[0] == L'/' || lineTest[0] == L';' || lineTest[0] == L'\r')
					continue;

				if (CParser::ContarCaracteres(lineTest,L"{") != CParser::ContarCaracteres(lineTest,L"}"))
				{
					g_Log.Add(CLog::Error, "Error en linea[%d] = %S ",linea, lineTest.c_str());
					error = true;
				}
				if (CParser::ContarCaracteres(lineTest,L"}") != CParser::ContarCaracteres(lineTest,L"}"))
				{
					g_Log.Add(CLog::Error, "Error en linea[%d] = %S ",linea, lineTest.c_str());
					error = true;
				}
			}
		}
	}

	if (!error)
	{

		wstring filew = ReadFileW(L".//Achivements.ini");
		if(filew.size() > 0)
		{
			m_Achiv.clear();

			bool leer = false;

			//-------------------------------------------------------------
			Achiv tmp_m_Achiv;
			memset(&tmp_m_Achiv, 0, sizeof(tmp_m_Achiv));
			//---------------------------------------------------------------

			wstringstream file(filew);
			wstring line;
			while(getline(file, line))
			{
			//	g_Log.Add(CLog::Error, "name[%S]", line.c_str());

				if(line.size() > 0)
				{
					if( line[0] == L'/' || line[0] == L';')
						continue;

//						line = Utils::ReplaceStringW(line, L"\"", L"", true);
//						line = Utils::ReplaceStringW(line, L"<", L"", true);
//						line = Utils::ReplaceStringW(line, L">", L"", true);
//						line = Utils::ReplaceStringW(line, L"/", L"", true);


					if( line.find(L"achivment_begin") == 0)
						leer = true;
						
					if(leer)
					{
						//g_Log.Add(CLog::Error, "%S [%d]", line.c_str(), line.find(L"id"));
						if( (int)line.find(L"id=") > 0)		//OK
						{
							tmp_m_Achiv.Id = Parser::ParseOptionInt(line, L"id");
//							g_Log.Add(CLog::Error, "id[%d][%d]",Parser::ParseOptionInt(line, L"id"),line.find(L"id"));

						}
						if( (int)line.find(L"position=") > 0)		//OK
						{
							tmp_m_Achiv.position = Parser::ParseOptionInt(line, L"position");
							//g_Log.Add(CLog::Error, "position[%d]",Parser::ParseOptionInt(line, L"position"));

						}
						if( (int)line.find(L"name=") > 0)		//OK
						{
							tmp_m_Achiv.name = Parser::ParseOptionStringConEspacios(line, L"name").c_str();
							//g_Log.Add(CLog::Error, "name[%S]",Parser::ParseOptionStringConEspacios(line, L"name").c_str());
						}
						if( (int)line.find(L"descripcion=") > 0)		//OK
						{
							tmp_m_Achiv.description = Parser::ParseOptionStringConEspacios(line, L"descripcion").c_str();
							//g_Log.Add(CLog::Error, "descripcion[%S]",Parser::ParseOptionStringConEspacios(line, L"descripcion").c_str());
						}
						if( (int)line.find(L"time_reset=") > 0)		//OK
						{
							tmp_m_Achiv.timeReset = Parser::ParseOptionInt(line, L"time_reset");
							//g_Log.Add(CLog::Error, "time_reset[%d]",Parser::ParseOptionInt(line, L"time_reset"));
						}
						if( (int)line.find(L"hwid_control=") > 0)		//OK
						{
							tmp_m_Achiv.hwid = Parser::ParseOptionInt(line, L"hwid_control");
							//g_Log.Add(CLog::Error, "hwid[%d]",Parser::ParseOptionInt(line, L"hwid"));
						}

						if( (int)line.find(L"name_message=") > 0)		//OK
						{
							tmp_m_Achiv.hwid = Parser::ParseOptionInt(line, L"name_message");
							//g_Log.Add(CLog::Error, "hwid[%d]",Parser::ParseOptionInt(line, L"hwid"));
						}




						if( (int)line.find(L"reward=") > 0)
						{
							//g_Log.Add(CLog::Error, "condicion[%S]",Parser::ParseOptionStringConEspacios(line, L"condicion").c_str());


							tstring sdrop =L"";
							sdrop = Utils::ReplaceStringW(line, L"{{", L"{", true);
							sdrop = Utils::ReplaceStringW(sdrop, L"}", L"", true);

							int contador2 = 0;
							std::wstring subs2;
							std::wstringstream wss2(sdrop);
							while(std::getline(wss2, subs2, L'{'))
							{
								if (contador2 <1)
								{
									contador2++;
									continue;
								}

								int contador3 = 0;
								AchivRewards info;
								wstring drop = Utils::ReplaceStringW(subs2, L";", L" ", true);
								tstringstream sstr2; sstr2 << drop;
								tstring drop2;
								while(sstr2 >> drop2)
								{
	//								g_Log.Add(CLog::Error, "PARAM[%S]",drop2.c_str());

									if (contador3 == 0)
										info.itemId = g_ObjectDB.GetClassIdFromName(drop2.c_str());
									else if (contador3 == 1)
										info.count = _wtoi(drop2.c_str());

									contador3++;
								}
								tmp_m_Achiv.data.RewardList.push_back(info);
								
							}

	//----------------------------------------------------------------------------------------------------------------------------------------------------
						}
						else if( (int)line.find(L"condicion=") > 0)
						{

							tstring sdrop =L"";
							sdrop = Utils::ReplaceStringW(line, L"{{", L"{", true);
							sdrop = Utils::ReplaceStringW(sdrop, L"}", L"", true);

							int contador2 = 0;
							std::wstring subs2;
							std::wstringstream wss2(sdrop);
							while(std::getline(wss2, subs2, L'{'))
							{
								if (contador2 <1)
								{
									contador2++;
									continue;
								}

								int contador3 = 0;
								ConditionBoss info_ConditionBoss;
								ConditionMob info_ConditionMob;
								ConditionItem info_ConditionItem;

								int condition = 0;

								wstring vars = Utils::ReplaceStringW(subs2, L";", L" ", true);
								tstringstream sstr2; sstr2 << vars;
								tstring vars2;
								while(sstr2 >> vars2)
								{
									//g_Log.Add(CLog::Error, "PARAM[%S]",vars2.c_str());

									if (contador3 == 0)
									{
										if(vars2 == L"BOSS")						condition = ENUM_BOSS;
										else if(vars2 == L"MOB")					condition = ENUM_MOB;
										else if(vars2 == L"ITEM")					condition = ENUM_ITEM;
										else if(vars2 == L"OLYMPIAD_WIN")			condition = ENUM_OLYMPIAD;
										else if(vars2 == L"DEATHMATCH")				condition = ENUM_DEATHMATCH;
										else if(vars2 == L"LASTTEAMSTANDING")		condition = ENUM_LASTTEAMSTANDING;
										else if(vars2 == L"DESTROYTHEBASE")			condition = ENUM_DESTROYTHEBASE;
										else if(vars2 == L"CAPTURETHEFLAG")			condition = ENUM_CAPTURETHEFLAG;
										else if(vars2 == L"SAVESCAPTURETHEFLAG")	condition = ENUM_SAVESCAPTURETHEFLAG;
										else if(vars2 == L"VOTE")					condition = ENUM_VOTE;
										else if(vars2 == L"PVP")					condition = ENUM_PVP;
										else if(vars2 == L"PK")						condition = ENUM_PK;
										else if(vars2 == L"LOGIN_DIARIO")			condition = ENUM_LOGIN;
										else if(vars2 == L"HERO")					condition = ENUM_HERO;
									}
									else if (contador3 == 1)
									{
										if(condition == ENUM_BOSS)
										{
											info_ConditionBoss.NpcId = g_ObjectDB.GetClassIdFromName(vars2.c_str());
											m_Achiv_Mobs.push_back(info_ConditionBoss.NpcId);
										}
										else if(condition == ENUM_MOB)
										{
											info_ConditionMob.NpcId = g_ObjectDB.GetClassIdFromName(vars2.c_str());
											m_Achiv_Mobs.push_back(info_ConditionMob.NpcId);
										}
										else if(condition == ENUM_ITEM)					info_ConditionItem.ItemId = g_ObjectDB.GetClassIdFromName(vars2.c_str());
										else if(condition == ENUM_OLYMPIAD)				tmp_m_Achiv.data.ConditionOlympiad = _wtoi(vars2.c_str());
										else if(condition == ENUM_DEATHMATCH)			tmp_m_Achiv.data.ConditionDeathMatch = _wtoi(vars2.c_str());
										else if(condition == ENUM_LASTTEAMSTANDING)		tmp_m_Achiv.data.ConditionLastTeamStanding = _wtoi(vars2.c_str());
										else if(condition == ENUM_DESTROYTHEBASE)		tmp_m_Achiv.data.ConditionDestroyTheBase = _wtoi(vars2.c_str());
										else if(condition == ENUM_CAPTURETHEFLAG)		tmp_m_Achiv.data.ConditionCaptureTheFlag = _wtoi(vars2.c_str());
										else if(condition == ENUM_SAVESCAPTURETHEFLAG)	tmp_m_Achiv.data.ConditionSavesCaptureTheFlag = _wtoi(vars2.c_str());
										else if(condition == ENUM_VOTE)					tmp_m_Achiv.data.ConditionVote = _wtoi(vars2.c_str());
										else if(condition == ENUM_PVP)					tmp_m_Achiv.data.ConditionPvP = _wtoi(vars2.c_str());
										else if(condition == ENUM_PK)					tmp_m_Achiv.data.ConditionPk = _wtoi(vars2.c_str());
										else if(condition == ENUM_LOGIN)				tmp_m_Achiv.data.ConditionLogin = _wtoi(vars2.c_str());
										else if(condition == ENUM_HERO)					tmp_m_Achiv.data.ConditionHero = _wtoi(vars2.c_str());
									}
									else if (contador3 == 2)
									{
										if(condition == ENUM_BOSS)						info_ConditionBoss.Counts = _wtoi(vars2.c_str());
										else if(condition == ENUM_MOB)					info_ConditionMob.Counts = _wtoi(vars2.c_str());
										else if(condition == ENUM_ITEM)					info_ConditionItem.Counts = _wtoi(vars2.c_str());
									}

									contador3++;
								}

								if (condition == ENUM_BOSS)
									tmp_m_Achiv.data.ListConditionBoss.push_back(info_ConditionBoss);
								else if (condition == ENUM_MOB)
									tmp_m_Achiv.data.ListConditionMob.push_back(info_ConditionMob);
								else if (condition == ENUM_ITEM)
									tmp_m_Achiv.data.ListConditionItem.push_back(info_ConditionItem);
								
							}
							//g_Log.Add(CLog::Error, "reward[%S]",Parser::ParseOptionStringConEspacios(line, L"reward").c_str());
						}
					}
					if( line.find(L"achivment_end") == 0)
					{
						m_Achiv.push_back(tmp_m_Achiv);

						memset(&tmp_m_Achiv, 0, sizeof(tmp_m_Achiv));
	//					Achiv tmp_m_Achiv = {0};
						
						//tmp_m_Achiv.data.RewardList.clear();

						leer = false;
					}

				}
			}
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find ..//Script//Achivements.txt !", __FUNCTION__);
		}

	/*
				g_Log.Add(CLog::Error, "m_Achiv_SIZE[%d]",m_Achiv.size());
				for(UINT n=0;n<m_Achiv.size();n++)	//LISTA DE CONFIGS
				{
					g_Log.Add(CLog::Error, "Id[%d] name[%S] description[%S] position[%d] timeReset[%d]", m_Achiv[n].Id, m_Achiv[n].name.c_str(), m_Achiv[n].description.c_str(),m_Achiv[n].position,m_Achiv[n].timeReset);


					g_Log.Add(CLog::Error, "ConditionOlympiad[%d]",m_Achiv[n].data.ConditionOlympiad);
					g_Log.Add(CLog::Error, "ConditionDeathMatch[%d]",m_Achiv[n].data.ConditionDeathMatch);
					g_Log.Add(CLog::Error, "ConditionLastTeamStanding[%d]",m_Achiv[n].data.ConditionLastTeamStanding);
					g_Log.Add(CLog::Error, "ConditionDestroyTheBase[%d]",m_Achiv[n].data.ConditionDestroyTheBase);
					g_Log.Add(CLog::Error, "ConditionCaptureTheFlag[%d]",m_Achiv[n].data.ConditionCaptureTheFlag);
					g_Log.Add(CLog::Error, "ConditionSavesCaptureTheFlag[%d]",m_Achiv[n].data.ConditionSavesCaptureTheFlag);
					g_Log.Add(CLog::Error, "ConditionVote[%d]",m_Achiv[n].data.ConditionVote);
					g_Log.Add(CLog::Error, "ConditionPvP[%d]",m_Achiv[n].data.ConditionPvP);
					g_Log.Add(CLog::Error, "ConditionPk[%d]",m_Achiv[n].data.ConditionPk);


					for(UINT i=0;i<m_Achiv[n].data.ListConditionBoss.size();i++)
					{
						INT32 NpcId = m_Achiv[n].data.ListConditionBoss[i].NpcId;
						INT32 Counts = m_Achiv[n].data.ListConditionBoss[i].Counts;

						g_Log.Add(CLog::Error, "ListConditionBoss: NpcId[%d] Counts[%d]",NpcId,Counts);
					}

					for(UINT i=0;i<m_Achiv[n].data.ListConditionMob.size();i++)
					{
						INT32 NpcId = m_Achiv[n].data.ListConditionMob[i].NpcId;
						INT32 Counts = m_Achiv[n].data.ListConditionMob[i].Counts;

						g_Log.Add(CLog::Error, "ListConditionMob: NpcId[%d] Counts[%d]",NpcId,Counts);
					}

					for(UINT i=0;i<m_Achiv[n].data.ListConditionItem.size();i++)
					{
						INT32 ItemId = m_Achiv[n].data.ListConditionItem[i].ItemId;
						INT32 Counts = m_Achiv[n].data.ListConditionItem[i].Counts;

						g_Log.Add(CLog::Error, "ListConditionItem: ItemId[%d] Counts[%d]",ItemId,Counts);
					}


					for(UINT i=0;i<m_Achiv[n].data.RewardList.size();i++)
					{
						INT32 ItemId = m_Achiv[n].data.RewardList[i].itemId;
						INT32 Count = m_Achiv[n].data.RewardList[i].count;


						g_Log.Add(CLog::Error, "RewardList: ItemId[%d] Count[%d]",ItemId,Count);
					}


					for(UINT n=0;n<m_Achiv.size();n++)
					{

			//			g_Log.Add(CLog::Error, "Id[%d] name[%S] description[%S] position[%d] timeReset[%d]", m_Achiv[n].Id, m_Achiv[n].name.c_str(), m_Achiv[n].description.c_str(),m_Achiv[n].position,m_Achiv[n].timeReset);
						//-----------------------NAME-----------------------------------
						{
							std::wstringstream wss;
							wss << "<?ACHIV_" << m_Achiv[n].Id << "_NAME?>";
							wstring buscar = wss.str();
							//size_t pos = wHtml.find(buscar);
			//				g_Log.Add(CLog::Error, "buscar[%S]", buscar.c_str());
							//while(pos != string::npos)
							//{
							//	wHtml = wHtml.replace(pos, buscar.size(),  m_Achiv[n].name);
							//	pos = wHtml.find(buscar);
							//}
						}
					}
					g_Log.Add(CLog::Error, "----------------------------------------");
				}

	//*/

	}

	unguard;
}

bool Achivments::UserExCommandAchivement(User *pUser, wstring params)
{
	guard;
	if(g_achiv)
	{
		wstring wHtml = g_HtmlCache.Get(L"achiv.htm");


		PlayerAction::ShowHTML(pUser, L"achiv.htm", wHtml.c_str(), 0);

	}
	unguard;
	return false;
}


wstring Achivments::ReplaceOptions(wstring wHtml, User* pUser)
{
	guard;

	for(UINT n=0;n<m_Achiv.size();n++)
	{
//		g_Log.Add(CLog::Error, "Id[%d] name[%S] description[%S] position[%d] timeReset[%d]", m_Achiv[n].Id, m_Achiv[n].name.c_str(), m_Achiv[n].description.c_str(),m_Achiv[n].position,m_Achiv[n].timeReset);
		//-----------------------NAME-----------------------------------
		{
			std::wstringstream wss;
			wss << "<?ACHIV_" << m_Achiv[n].Id << "_NAME?>";
			wstring buscar = wss.str();
			size_t pos = wHtml.find(buscar);
			
			while(pos != string::npos)
			{
				wHtml = wHtml.replace(pos, buscar.size(),  m_Achiv[n].name);
				pos = wHtml.find(buscar);
			}
		}
		//---------------------------------------------------------------
		//-----------------------DESCRIPCION-----------------------------------
		{
			std::wstringstream wss;
			wss << "<?ACHIV_" << m_Achiv[n].Id << "_DESCRIPCION?>";
			wstring buscar = wss.str();
			size_t pos = wHtml.find(buscar);
			while(pos != string::npos)
			{
				wHtml = wHtml.replace(pos, buscar.size(),  m_Achiv[n].description);
				pos = wHtml.find(buscar);
			}
		}
		//---------------------------------------------------------------
		//-----------------------BYPASS-----------------------------------
		{
			std::wstringstream wss;
			wss << "<?ACHIV_" << m_Achiv[n].Id << "_BYPASS?>";
			wstring buscar = wss.str();
			size_t pos = wHtml.find(buscar);
			while(pos != string::npos)
			{
				std::wstringstream wss2;
				wss2 << "bypass achiv_reward?id=" << m_Achiv[n].Id;
				wstring bypass = wss2.str();

				wHtml = wHtml.replace(pos, buscar.size(), bypass);
				pos = wHtml.find(buscar);
			}
		}
		//---------------------------------------------------------------
		//-----------------------BUTTONVALUE-----------------------------------
		{
			std::wstringstream wss;
			wss << "<?ACHIV_" << m_Achiv[n].Id << "_BUTTONVALUE?>";
			wstring buscar = wss.str();
			size_t pos = wHtml.find(buscar);
			while(pos != string::npos)
			{
				std::map<INT32, AchivEstadoUser>::iterator i(pUser->pED->AchivSystem.ListAchivState.find(m_Achiv[n].Id));
				if (i == pUser->pED->AchivSystem.ListAchivState.end()) {
//					g_Log.Add(CLog::Error, "NO LO ENCONTRO", buscar.c_str());
				} else {
					if (i->second == ENUM_ENPROCESO)
						wHtml = wHtml.replace(pos, buscar.size(), L"En Proceso");
					else if(i->second == ENUM_PARACOBRAR)
						wHtml = wHtml.replace(pos, buscar.size(), L"Recompensa");
					else if(i->second == ENUM_FINALIZADO)
					{
						wHtml = wHtml.replace(pos, buscar.size(), L"Finalizado");
					}
				}				
				pos = wHtml.find(buscar);
			}
		}
		//---------------------------------------------------------------
		//-----------------------PLAYER_-----------------------------------
		{
			for(UINT i=0;i<ENUM_ZIZE;i++)
			{
				for(UINT u=0;u<10;u++)
				{	wstring reemplazo = L"";
					std::wstringstream wss;
					wss << "<?PLAYER_" << m_Achiv[n].Id << "_" << i << "_" << u << "?>";
					wstring buscar = wss.str();
					size_t pos = wHtml.find(buscar);
					while(pos != string::npos)
					{
						//g_Log.Add(CLog::Error, "buscar[%S]", buscar.c_str());
						if (i == ENUM_OLYMPIAD)					reemplazo = Utils::IntToWString(pUser->pED->AchivSystem.Olympiad);
						if (i == ENUM_DEATHMATCH)				reemplazo = Utils::IntToWString(pUser->pED->AchivSystem.DeathMatch);
						if (i == ENUM_LASTTEAMSTANDING)			reemplazo = Utils::IntToWString(pUser->pED->AchivSystem.LastTeamStanding);
						if (i == ENUM_DESTROYTHEBASE)			reemplazo = Utils::IntToWString(pUser->pED->AchivSystem.DestroyTheBase);
						if (i == ENUM_CAPTURETHEFLAG)			reemplazo = Utils::IntToWString(pUser->pED->AchivSystem.CaptureTheFlag);
						if (i == ENUM_SAVESCAPTURETHEFLAG)		reemplazo = Utils::IntToWString(pUser->pED->AchivSystem.SavesCaptureTheFlag);
						if (i == ENUM_PVP)						reemplazo = Utils::IntToWString(pUser->pED->AchivSystem.PvP);
						if (i == ENUM_BOSS)
						{
							if (m_Achiv[n].data.ListConditionBoss.size()>u-1)
							{
								std::map<INT32, INT32>::iterator i(pUser->pED->AchivSystem.KillMobCounts.find(m_Achiv[n].data.ListConditionBoss[u-1].NpcId));
								if (i == pUser->pED->AchivSystem.KillMobCounts.end()) {
//									g_Log.Add(CLog::Error, "NO LO ENCONTRO", buscar.c_str());
								} else {
									reemplazo = Utils::IntToWString(i->second);
								}
							}
						}
						else if (i == ENUM_MOB)
						{
							if (m_Achiv[n].data.ListConditionMob.size()>u-1)
							{
								std::map<INT32, INT32>::iterator i(pUser->pED->AchivSystem.KillMobCounts.find(m_Achiv[n].data.ListConditionMob[u-1].NpcId));
								if (i == pUser->pED->AchivSystem.KillMobCounts.end()) {
//									g_Log.Add(CLog::Error, "NO LO ENCONTRO", buscar.c_str());
								} else {
									reemplazo = Utils::IntToWString(i->second);
								}
							}
						}
						else if (i == ENUM_ITEM)
						{
							if (m_Achiv[n].data.ListConditionItem.size()>u-1)
							{
								CItem *pItem = pUser->inventory.GetItemByDBID(m_Achiv[n].data.ListConditionItem[u-1].ItemId);
								if(pItem)
								{
									reemplazo = Utils::IntToWString(pItem->pSID->nItemAmount);
								}

							}
						}
						if (i == ENUM_PK)						reemplazo = Utils::IntToWString(pUser->pED->AchivSystem.Pk);
						if (i == ENUM_LOGIN)					reemplazo = Utils::IntToWString(pUser->pED->AchivSystem.Login);
						if (i == ENUM_HERO)						reemplazo = Utils::IntToWString(pUser->pED->AchivSystem.Hero);

						wHtml = wHtml.replace(pos, buscar.size(),  reemplazo);
						pos = wHtml.find(buscar);
					}
				}
			}
		}
		//---------------------------------------------------------------
		//---------------------------------------------------------------
		//-----------------------ACHIV_-----------------------------------
		{
			for(UINT i=0;i<ENUM_ZIZE;i++)
			{
				for(UINT u=0;u<10;u++)
				{	wstring reemplazo = L"";
					std::wstringstream wss;
					wss << "<?ACHIV_" << m_Achiv[n].Id << "_" << i << "_" << u << "?>";
					wstring buscar = wss.str();
					size_t pos = wHtml.find(buscar);
					while(pos != string::npos)
					{
						//g_Log.Add(CLog::Error, "buscar[%S]", buscar.c_str());
						if (i == ENUM_OLYMPIAD)						reemplazo = Utils::IntToWString(m_Achiv[n].data.ConditionOlympiad);
						else if (i == ENUM_DEATHMATCH)				reemplazo = Utils::IntToWString(m_Achiv[n].data.ConditionDeathMatch);
						else if (i == ENUM_LASTTEAMSTANDING)		reemplazo = Utils::IntToWString(m_Achiv[n].data.ConditionLastTeamStanding);
						else if (i == ENUM_DESTROYTHEBASE)			reemplazo = Utils::IntToWString(m_Achiv[n].data.ConditionDestroyTheBase);
						else if (i == ENUM_CAPTURETHEFLAG)			reemplazo = Utils::IntToWString(m_Achiv[n].data.ConditionCaptureTheFlag);
						else if (i == ENUM_SAVESCAPTURETHEFLAG)		reemplazo = Utils::IntToWString(m_Achiv[n].data.ConditionSavesCaptureTheFlag);
						else if (i == ENUM_PVP)						reemplazo = Utils::IntToWString(m_Achiv[n].data.ConditionPvP);
						else if (i == ENUM_BOSS)
						{
							if (m_Achiv[n].data.ListConditionBoss.size()>u-1)
								reemplazo = Utils::IntToWString(m_Achiv[n].data.ListConditionBoss[u-1].Counts);
						}
						else if (i == ENUM_MOB)
						{
							if (m_Achiv[n].data.ListConditionMob.size()>u-1)
								reemplazo = Utils::IntToWString(m_Achiv[n].data.ListConditionMob[u-1].Counts);
						}
						else if (i == ENUM_ITEM)
						{
							if (m_Achiv[n].data.ListConditionItem.size()>u-1)
								reemplazo = Utils::IntToWString(m_Achiv[n].data.ListConditionItem[u-1].Counts);
						}
						else if (i == ENUM_PK)						reemplazo = Utils::IntToWString(m_Achiv[n].data.ConditionPk);
						else if (i == ENUM_LOGIN)					reemplazo = Utils::IntToWString(m_Achiv[n].data.ConditionLogin);
						else if (i == ENUM_HERO)					reemplazo = Utils::IntToWString(m_Achiv[n].data.ConditionHero);

						wHtml = wHtml.replace(pos, buscar.size(),  reemplazo);
						pos = wHtml.find(buscar);
					}
				}
			}
		}
		//---------------------------------------------------------------
			//<?ACHIV_1_NAME?>
			//<?ACHIV_1_DESCRIPCION?>
			//<?ACHIV_1_BUTTONVALUE?>
			//<?ACHIV_1_BYPASS?>

//-------------------------------------------------------------------------------------
//			size_t pos = wHtml.find(buscar);
//			while(pos != string::npos)
//			{
//				wHtml = wHtml.replace(pos, buscar.size(), resultado);
//				if(all)
//					pos = wHtml.find(buscar);
//			else
//					pos = wstring::npos;
//			}

	}

	unguard;
	return wHtml;
}

bool Achivments::Bypass(User* pUser, wstring wBypass)
{
	if( wBypass.find(L"xxxxxxxxxxxxxxxx?") == 0)
	{
		return true;
	}else if(wBypass.find(L"get_daily?") == 0)
	{
		wstring wHtml = g_HtmlCache.Get(L"achiv_daily.htm");

		wHtml = ReplaceOptions(wHtml, pUser); 

		pUser->pED->AchivSystem.UltimoHTML = L"achiv_daily.htm";

		PlayerAction::ShowHTML(pUser, L"achiv_daily.htm", wHtml.c_str(), 0);
		return true;
	}else if(wBypass.find(L"get_pvp?") == 0)
	{
		wstring wHtml = g_HtmlCache.Get(L"achiv_pvp.htm");

		wHtml = ReplaceOptions(wHtml, pUser);
		pUser->pED->AchivSystem.UltimoHTML = L"achiv_pvp.htm";

		PlayerAction::ShowHTML(pUser, L"achiv_pvp.htm", wHtml.c_str(), 0);
		return true;
	}else if(wBypass.find(L"get_tvt?") == 0)
	{
		wstring wHtml = g_HtmlCache.Get(L"achiv_tvt.htm");

		wHtml = ReplaceOptions(wHtml, pUser);
		pUser->pED->AchivSystem.UltimoHTML = L"achiv_tvt.htm";

		PlayerAction::ShowHTML(pUser, L"achiv_tvt.htm", wHtml.c_str(), 0);

		return true;
	}else if(wBypass.find(L"get_oly?") == 0)
	{
		wstring wHtml = g_HtmlCache.Get(L"achiv_olympiad.htm");

		wHtml = ReplaceOptions(wHtml, pUser);
		pUser->pED->AchivSystem.UltimoHTML = L"achiv_olympiad.htm";

		PlayerAction::ShowHTML(pUser, L"achiv_olympiad.htm", wHtml.c_str(), 0);
		return true;
	}else if(wBypass.find(L"get_boss?") == 0)
	{
		wstring wHtml = g_HtmlCache.Get(L"achiv_boss.htm");

		wHtml = ReplaceOptions(wHtml, pUser);
		pUser->pED->AchivSystem.UltimoHTML = L"achiv_boss.htm";

		PlayerAction::ShowHTML(pUser, L"achiv_boss.htm", wHtml.c_str(), 0);

		return true;
	}else if(wBypass.find(L"get_epic?") == 0)
	{
		wstring wHtml = g_HtmlCache.Get(L"achiv_bossepic.htm");

		wHtml = ReplaceOptions(wHtml, pUser);
		pUser->pED->AchivSystem.UltimoHTML = L"achiv_bossepic.htm";

		PlayerAction::ShowHTML(pUser, L"achiv_bossepic.htm", wHtml.c_str(), 0);
		return true;
	}else if(wBypass.find(L"achiv_reward?") == 0)
	{
		INT32 id = Parser::GetBypassValueInt(wBypass.c_str(), L"id");

		Rewards(pUser, id);

		return true;
	}

	return false;
}




void Achivments::Rewards(User* pUser, INT32 Id)
{
	guard;
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		for(UINT n=0;n<m_Achiv.size();n++)	//LISTA DE CONFIGS
		{
			if(m_Achiv[n].Id == Id)
			{
				bool entregar = true;
				bool messageInsuficient = true;
				bool messageHwid = false;


				//INSERTAR HWID EN EL MAP
				if(m_Achiv[n].hwid && VerificarHwid(pUser, m_Achiv[n].Id, m_Achiv[n].timeReset))
				{
					entregar = false;
					messageInsuficient = false;
					messageHwid = true;
				}

				std::map<INT32, INT32>::iterator w(pUser->pED->AchivSystem.ListAchivTime.find(m_Achiv[n].Id));
				if (w == pUser->pED->AchivSystem.ListAchivTime.end()) 
				{
					entregar = false;
					messageInsuficient = false;
				}
				else 
				{
					if(w->second + m_Achiv[n].timeReset > time(0))
					{
						entregar = false;
						messageInsuficient = false;
					}
				}

				std::map<INT32, AchivEstadoUser>::iterator i(pUser->pED->AchivSystem.ListAchivState.find(m_Achiv[n].Id));
				if (i == pUser->pED->AchivSystem.ListAchivState.end()) 
					entregar = false;
				else 
				{
					if (i->second == ENUM_ENPROCESO)
						entregar = false;
				}


				if(m_Achiv[n].data.ConditionOlympiad > pUser->pED->AchivSystem.Olympiad)
				{
					entregar = false;
				}

				if(m_Achiv[n].data.ConditionDeathMatch > pUser->pED->AchivSystem.DeathMatch)
				{
					entregar = false;
				}

				if(m_Achiv[n].data.ConditionLastTeamStanding > pUser->pED->AchivSystem.LastTeamStanding)
				{
					entregar = false;
				}

				if(m_Achiv[n].data.ConditionDestroyTheBase > pUser->pED->AchivSystem.DestroyTheBase)
				{
					entregar = false;
				}

				if(m_Achiv[n].data.ConditionCaptureTheFlag > pUser->pED->AchivSystem.CaptureTheFlag)
				{
					entregar = false;
				}

				if(m_Achiv[n].data.ConditionSavesCaptureTheFlag > pUser->pED->AchivSystem.SavesCaptureTheFlag)
				{
					entregar = false;
				}

				if(m_Achiv[n].data.ConditionVote > pUser->pED->AchivSystem.Vote)
				{
					entregar = false;
				}

				if(m_Achiv[n].data.ConditionPvP > pUser->pED->AchivSystem.PvP)
				{
					entregar = false;
				}

				if(m_Achiv[n].data.ConditionPk > pUser->pED->AchivSystem.Pk)
				{
					entregar = false;
				}

				if(m_Achiv[n].data.ConditionHero > pUser->pED->AchivSystem.Hero)
				{
					entregar = false;
				}


				{
					for(UINT i=0;i<m_Achiv[n].data.ListConditionBoss.size();i++)
					{
						INT32 NpcId = m_Achiv[n].data.ListConditionBoss[i].NpcId;
						INT32 Counts = m_Achiv[n].data.ListConditionBoss[i].Counts;

						std::map<INT32, INT32>::iterator u(pUser->pED->AchivSystem.KillMobCounts.find(NpcId));
						if (u == pUser->pED->AchivSystem.KillMobCounts.end()) 
						{
							entregar = false;
						}
						else 
						{
							if(Counts > u->second)
								entregar = false;
						}
					}
				}

				{
					for(UINT i=0;i<m_Achiv[n].data.ListConditionMob.size();i++)
					{
						INT32 NpcId = m_Achiv[n].data.ListConditionMob[i].NpcId;
						INT32 Counts = m_Achiv[n].data.ListConditionMob[i].Counts;

						std::map<INT32, INT32>::iterator u(pUser->pED->AchivSystem.KillMobCounts.find(NpcId));
						if (u == pUser->pED->AchivSystem.KillMobCounts.end()) 
						{
							entregar = false;
						}
						else 
						{
							if(Counts > u->second)
								entregar = false;
						}
					}
				}
							
				{
					for(UINT i=0;i<m_Achiv[n].data.ListConditionItem.size();i++)
					{
						INT32 ItemId = m_Achiv[n].data.ListConditionItem[i].ItemId;
						INT32 Counts = m_Achiv[n].data.ListConditionItem[i].Counts;

						CItem *pItem = pUser->inventory.GetItemByDBID(ItemId);
						if(pItem)
						{
							if(Counts > pItem->pSID->nItemAmount)
							{
								entregar = false;
							}
						}
						else
						{
							entregar = false;
						}
					}
				}

				if (entregar)
				{
					int entregado = true;
					UINT contador = 0;
					for(UINT i=0;i<m_Achiv[n].data.RewardList.size();i++)
					{
						INT32 ItemId = m_Achiv[n].data.RewardList[i].itemId;
						INT32 Count = m_Achiv[n].data.RewardList[i].count;

						if(pUser->inventory.CheckAddable(ItemId, Count))
						{
							pUser->AddItemToInventory(ItemId, Count);
							contador++;
						}
						else
						{
							for(UINT z=0;z<contador;z++)
							{
								INT32 ItemId = m_Achiv[n].data.RewardList[z].itemId;
								INT32 Count = m_Achiv[n].data.RewardList[z].count;
								pUser->DeleteItemInInventory(ItemId, Count);
							}

							CSystemMessage msg1(SystemMessage::S1_POPUP);
							msg1.AddText(L"Nesesitas mas espacio en el inventario.");
							pUser->pSocket->SendSystemMessage(&msg1);
							entregado = false;
							break;
						}
					}

					if (entregado)
					{
						std::map<INT32, AchivEstadoUser>::iterator i(pUser->pED->AchivSystem.ListAchivState.find(m_Achiv[n].Id));
						if (i == pUser->pED->AchivSystem.ListAchivState.end()) 
							entregar = false;
						else 
						{
							i->second = ENUM_FINALIZADO;
						}

						std::map<INT32, INT32>::iterator w(pUser->pED->AchivSystem.ListAchivTime.find(m_Achiv[n].Id));
						if (w == pUser->pED->AchivSystem.ListAchivTime.end()) 
						{

						}
						else 
						{
							w->second = time(0);
						}

						wstring wHtml = g_HtmlCache.Get(pUser->pED->AchivSystem.UltimoHTML);
						wHtml = ReplaceOptions(wHtml, pUser);
						PlayerAction::ShowHTML(pUser, pUser->pED->AchivSystem.UltimoHTML.c_str() , wHtml.c_str(), 0);

						CSystemMessage msg1(SystemMessage::S1_POPUP);
						msg1.AddText(L"Mision cumplida! Felicidades!!!, Hemos entregado tu recompenza!");
						pUser->pSocket->SendSystemMessage(&msg1);

						Save(pUser);

						//INSERTAR HWID EN EL MAP
						if(m_Achiv[n].hwid)
						{
							//g_Log.Add(CLog::Error, "insetro");
							AchivHWID tmp_AchivHwid;

							tmp_AchivHwid.AchivId = 0;
							tmp_AchivHwid.time = 0;

							tmp_AchivHwid.AchivId = m_Achiv[n].Id;
							memcpy(tmp_AchivHwid.hwid, pUser->pSocket->pED->longHWID.hash, 32);
							tmp_AchivHwid.time = time(0);
							HWIDs.push_back(tmp_AchivHwid);	
							DB_SaveHWIDs();
						}
					}
				}
				else
				{
					if(messageInsuficient)
					{
						CSystemMessage msg1(SystemMessage::S1_POPUP);
						msg1.AddText(L"Por el momento no reunes los requisitos para cobrar la recompenza!");
						pUser->pSocket->SendSystemMessage(&msg1);
					}
					else if(messageHwid)
					{
						CSystemMessage msg1(SystemMessage::S1_POPUP);
						msg1.AddText(L"Ya hemos entregado esta recompenza!");
						pUser->pSocket->SendSystemMessage(&msg1);
					}
				}
				break;
			}
		}

	}
	unguard;
}


bool Achivments::VerificarHwid(User* pUser, INT32 AchivId, INT32 timeReset)
{
	guard;

	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		for(UINT n=0;n<HWIDs.size();n++)
		{
			if (HWIDs[n].AchivId == AchivId)
			{
	//			g_Log.Add(CLog::Error, "111111111111");
				if(!memcmp(HWIDs[n].hwid, pUser->pSocket->pED->longHWID.hash, 32))
				{
	//				g_Log.Add(CLog::Error, "22222222222222222");
					if(HWIDs[n].time > time(0)-timeReset)
					{
	//					g_Log.Add(CLog::Error, "444444444444444");
						unguard;
						return true;
					}
				}
			}
		}
	}

	unguard;
	return false;
}

//-----------------------------SET USER POINTS----------------------------------

void Achivments::SetUser_Olympiad(User* pUser)		//OK
{
	guard;
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);
		pUser->pED->AchivSystem.Olympiad++;
		pUser->pED->AchivSystem.Save = true;
		pUser->pED->AchivSystem.HayCambio = true;
		//g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.Olympiad[%d]", pUser->pED->AchivSystem.Olympiad);
	}

	unguard;
}

void Achivments::SetUser_DeathMatch(User* pUser)		//OK
{
	guard;
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);
		pUser->pED->AchivSystem.DeathMatch++;
		pUser->pED->AchivSystem.Save = true;
		pUser->pED->AchivSystem.HayCambio = true;
		//g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.DeathMatch[%d]", pUser->pED->AchivSystem.DeathMatch);
	}

	unguard;
}

void Achivments::SetUser_LastTeamStanding(User* pUser)		//OK
{
	guard;
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);
		pUser->pED->AchivSystem.LastTeamStanding++;
		pUser->pED->AchivSystem.Save = true;
		pUser->pED->AchivSystem.HayCambio = true;
		//g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.LastTeamStanding[%d]", pUser->pED->AchivSystem.LastTeamStanding);
	}

	unguard;
}

void Achivments::SetUser_DestroyTheBase(User* pUser)		//OK
{
	guard;
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);
		pUser->pED->AchivSystem.DestroyTheBase++;
		pUser->pED->AchivSystem.Save = true;
		pUser->pED->AchivSystem.HayCambio = true;
		//g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.DestroyTheBase[%d]", pUser->pED->AchivSystem.DestroyTheBase);
	}
	unguard;
}

void Achivments::SetUser_CaptureTheFlag(User* pUser)		//OK
{
	guard;
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);
		pUser->pED->AchivSystem.CaptureTheFlag++;
		pUser->pED->AchivSystem.Save = true;
		pUser->pED->AchivSystem.HayCambio = true;
		//g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.CaptureTheFlag[%d]", pUser->pED->AchivSystem.CaptureTheFlag);
	}

	unguard;
}

void Achivments::SetUser_SavesCaptureTheFlag(User* pUser)		//OK
{
	guard;
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);
		pUser->pED->AchivSystem.SavesCaptureTheFlag++;
		pUser->pED->AchivSystem.Save = true;
		pUser->pED->AchivSystem.HayCambio = true;
		//g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.SavesCaptureTheFlag[%d]", pUser->pED->AchivSystem.SavesCaptureTheFlag);
	}

	unguard;
}

void Achivments::SetUser_PvP(User* pUser)				//OK
{
	guard;

	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);
		if(pUser->pED->tvtUser.status == TvT::UserNone)
		{
			pUser->pED->AchivSystem.PvP++;
			pUser->pED->AchivSystem.Save = true;
			pUser->pED->AchivSystem.HayCambio = true;
		}
	}

	//g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.PvP[%d]", pUser->pED->AchivSystem.PvP);

	unguard;
}

void Achivments::SetUser_Pk(User* pUser)				//OK
{
	guard;
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);
		pUser->pED->AchivSystem.Pk++;
		pUser->pED->AchivSystem.Save = true;
		//g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.Pk[%d]", pUser->pED->AchivSystem.Pk);
		pUser->pED->AchivSystem.HayCambio = true;
	}
	unguard;
}

void Achivments::SetUser_Hero(User* pUser)			//OK
{
	guard;
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);
		pUser->pED->AchivSystem.Hero++;
		pUser->pED->AchivSystem.Save = true;
		//g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.Hero[%d]", pUser->pED->AchivSystem.Hero);
	}

	unguard;
}

void Achivments::SetUser_Login(User* pUser)
{
	guard;
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);
		pUser->pED->AchivSystem.Login++;
		pUser->pED->AchivSystem.Save = true;
		//g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.Login[%d]", pUser->pED->AchivSystem.Login);
	}
	unguard;
}

void Achivments::SetUser_Vote(User* pUser)
{
	guard;
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		pUser->pED->AchivSystem.Vote++;
		pUser->pED->AchivSystem.Save = true;
		pUser->pED->AchivSystem.HayCambio = true;
		//g_Log.Add(CLog::Error, "pUser->pED->AchivSystem.Vote[%d]", pUser->pED->AchivSystem.Vote);
	}
	unguard;
}


void Achivments::SetUser_KillMob(CNPC* pNpc, CCreature* pKiller)
{
	guard;

	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		INT32 MobId = pNpc->pSD->nNpcClassID;

		if(pNpc->ValidCreature())
		{
			User* pUser = pKiller->GetUser();

			if(pUser->ValidUser())
			{
				if(pNpc->IsBoss())
				{
					if(CParty *pParty = pUser->GetParty())
					{
						UserVector members;
						pParty->GetAllMembersInRange(members, pNpc->pSD->Pos, 1500);

						vector<BYTE*> hwid;

						for(UINT n=0;n<members.size();n++)
						{
							if(User *pMember = members[n]->SafeCastUser())
							{
								for(UINT i=0;i<m_Achiv_Mobs.size();i++)
								{
									if(MobId == m_Achiv_Mobs[i])
									{
										std::map<INT32, INT32>::iterator j(pMember->pED->AchivSystem.KillMobCounts.find(MobId));
										if (j == pMember->pED->AchivSystem.KillMobCounts.end()) {
											pMember->pED->AchivSystem.KillMobCounts.insert ( std::pair<INT32,INT32>(MobId,1) );
											pMember->pED->AchivSystem.Save = true;
											pMember->pED->AchivSystem.HayCambio = true;
										} else {
											bool entregar = true;
											for(UINT h=0;h<hwid.size();h++)
											{
												if(!memcmp(hwid[h], pMember->pSocket->pED->longHWID.hash, 32))
													entregar=false;
											}

											entregar=true;
											if(entregar)
											{
												hwid.push_back(pMember->pSocket->pED->longHWID.hash);
												j->second++;
												pMember->pED->AchivSystem.Save = true;
												pMember->pED->AchivSystem.HayCambio = true;
											}
											//g_Log.Add(CLog::Error, "AchivSystem.KillMobCounts MobId[%d] Add Party Players", MobId);
										}
									}
								}
							}
						}
					}
					else
					{
						for(UINT i=0;i<m_Achiv_Mobs.size();i++)
						{
							if(MobId == m_Achiv_Mobs[i])
							{
								std::map<INT32, INT32>::iterator j(pUser->pED->AchivSystem.KillMobCounts.find(MobId));
								if (j == pUser->pED->AchivSystem.KillMobCounts.end()) {
									pUser->pED->AchivSystem.KillMobCounts.insert ( std::pair<INT32,INT32>(MobId,1) );
									pUser->pED->AchivSystem.Save = true;
									pUser->pED->AchivSystem.HayCambio = true;
								} else {
									j->second++;
									//g_Log.Add(CLog::Error, "AchivSystem.KillMobCounts MobId[%d] Boss Single", MobId);
									pUser->pED->AchivSystem.Save = true;
									pUser->pED->AchivSystem.HayCambio = true;
								}
							}
						}
					}
				}
				else
				{
					for(UINT i=0;i<m_Achiv_Mobs.size();i++)
					{
						if(MobId == m_Achiv_Mobs[i])
						{
							std::map<INT32, INT32>::iterator j(pUser->pED->AchivSystem.KillMobCounts.find(MobId));
							if (j == pUser->pED->AchivSystem.KillMobCounts.end()) {
								pUser->pED->AchivSystem.KillMobCounts.insert ( std::pair<INT32,INT32>(MobId,1) );
								pUser->pED->AchivSystem.Save = true;
								pUser->pED->AchivSystem.HayCambio = true;
							} else {
								j->second++;
								//g_Log.Add(CLog::Error, "AchivSystem.KillMobCounts MobId[%d]", MobId);
								pUser->pED->AchivSystem.Save = true;
								pUser->pED->AchivSystem.HayCambio = true;
							}
						}
					}
				}
			}
		}
	}
	unguard;
}


//VERIFICAR SI ESTAN PARA COBRAR

void Achivments::VerificarParaCobrar(User* pUser)	//OK
{
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		for(UINT n=0;n<m_Achiv.size();n++)	//LISTA DE CONFIGS
		{
			int achivId = m_Achiv[n].Id;

			int timeuser = 0;
			int state = 0;

			
			std::map<INT32, AchivEstadoUser>::iterator Iter(pUser->pED->AchivSystem.ListAchivState.find(achivId));
			if (Iter != pUser->pED->AchivSystem.ListAchivState.end()) 
			{
				state = Iter->second;
			}
			
			std::map<INT32, INT32>::iterator i(pUser->pED->AchivSystem.ListAchivTime.find(achivId));
			if (i != pUser->pED->AchivSystem.ListAchivTime.end()) 
			{
				timeuser = i->second;
			}

			{
				if (state == ENUM_ENPROCESO)
				{
					bool completo = true;

					if(m_Achiv[n].data.ConditionOlympiad > pUser->pED->AchivSystem.Olympiad)							completo = false;
					if(m_Achiv[n].data.ConditionDeathMatch > pUser->pED->AchivSystem.DeathMatch)						completo = false;
					if(m_Achiv[n].data.ConditionLastTeamStanding > pUser->pED->AchivSystem.LastTeamStanding)			completo = false;
					if(m_Achiv[n].data.ConditionDestroyTheBase > pUser->pED->AchivSystem.DestroyTheBase)				completo = false;
					if(m_Achiv[n].data.ConditionCaptureTheFlag > pUser->pED->AchivSystem.CaptureTheFlag)				completo = false;
					if(m_Achiv[n].data.ConditionSavesCaptureTheFlag > pUser->pED->AchivSystem.SavesCaptureTheFlag)		completo = false;
					if(m_Achiv[n].data.ConditionVote > pUser->pED->AchivSystem.Vote)									completo = false;
					if(m_Achiv[n].data.ConditionPvP > pUser->pED->AchivSystem.PvP)										completo = false;
					if(m_Achiv[n].data.ConditionPk > pUser->pED->AchivSystem.Pk)										completo = false;
					if(m_Achiv[n].data.ConditionHero > pUser->pED->AchivSystem.Hero)									completo = false;

					{
						for(UINT i=0;i<m_Achiv[n].data.ListConditionBoss.size();i++)
						{
							INT32 NpcId = m_Achiv[n].data.ListConditionBoss[i].NpcId;
							INT32 Counts = m_Achiv[n].data.ListConditionBoss[i].Counts;

							std::map<INT32, INT32>::iterator u(pUser->pED->AchivSystem.KillMobCounts.find(NpcId));
							if (u == pUser->pED->AchivSystem.KillMobCounts.end()) 
							{
								completo = false;
							}
							else 
							{
								if(Counts > u->second)
									completo = false;
							}
						}
					}

					{
						for(UINT i=0;i<m_Achiv[n].data.ListConditionMob.size();i++)
						{
							INT32 NpcId = m_Achiv[n].data.ListConditionMob[i].NpcId;
							INT32 Counts = m_Achiv[n].data.ListConditionMob[i].Counts;

							std::map<INT32, INT32>::iterator u(pUser->pED->AchivSystem.KillMobCounts.find(NpcId));
							if (u == pUser->pED->AchivSystem.KillMobCounts.end()) 
							{
								completo = false;
							}
							else 
							{
								if(Counts > u->second)
									completo = false;
							}
						}
					}
									
					{
						for(UINT i=0;i<m_Achiv[n].data.ListConditionItem.size();i++)
						{
							INT32 ItemId = m_Achiv[n].data.ListConditionItem[i].ItemId;
							INT32 Counts = m_Achiv[n].data.ListConditionItem[i].Counts;

							CItem *pItem = pUser->inventory.GetItemByDBID(ItemId);
							if(pItem)
							{
								if(Counts > pItem->pSID->nItemAmount)
								{
									completo = false;
								}
							}
							else
							{
								completo = false;
							}
						}
					}

					if(completo)
					{
						Iter->second = ENUM_PARACOBRAR;
						pUser->pED->AchivSystem.Save = true;





						std::wstringstream wss;
						wss << "Ya puedes cobrar el achivment: " << m_Achiv[n].name_message  << " Felicidades!!!";
						wstring mensaje = wss.str();
						pUser->SendSystemMessageRed(mensaje.c_str());

		//					std::map<INT32, AchivEstadoUser>::iterator i(pUser->pED->AchivSystem.ListAchivState.find(achivId));
		//					if (i == pUser->pED->AchivSystem.ListAchivState.end()) 
		//						;
		//					else 
		//					{
	//							g_Log.Add(CLog::Error, "fffff[%d]fffffff[%d]",i->first, i->second);
		//						i->second = ENUM_PARACOBRAR;
		//					}



					}
				}
			}
		}

	}

}


void Achivments::Save(User* pUser)	//OK
{
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		pUser->pED->AchivSystem.Save = false;
		g_Achivments.DB_SaveCharacterData_1(pUser);
		g_Achivments.DB_SaveCharacterData_2(pUser);
		g_Achivments.DB_SaveCharacterData_3(pUser);
		//g_Log.Add(CLog::Error, "save");
	}
}

void Achivments::TimerExpired(User* pUser)	//OK
{
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		if((pUser->pSD->nTimerTick % 5) == 0 )	
		{
			//if(pUser->pED->AchivSystem.HayCambio)
				VerificarParaCobrar(pUser);
		}

		if((pUser->pSD->nTimerTick % 20) == 0 )	
		{
				for(UINT n=0;n<m_Achiv.size();n++)	//LISTA DE CONFIGS
				{
					int achivId = m_Achiv[n].Id;

					int timeuser = 0;
					int state = 0;

					std::map<INT32, AchivEstadoUser>::iterator Iter(pUser->pED->AchivSystem.ListAchivState.find(achivId));
					if (Iter != pUser->pED->AchivSystem.ListAchivState.end()) 
					{
						state = Iter->second;
					}

					std::map<INT32, INT32>::iterator i(pUser->pED->AchivSystem.ListAchivTime.find(achivId));
					if (i != pUser->pED->AchivSystem.ListAchivTime.end()) 
					{
						timeuser = i->second;
					}


					{
						if (state == ENUM_FINALIZADO)
						{
							if(time(0)> timeuser + m_Achiv[n].timeReset)
							{
								{
									if(m_Achiv[n].data.ConditionOlympiad > 0)				pUser->pED->AchivSystem.Olympiad = 0;
									if(m_Achiv[n].data.ConditionDeathMatch > 0)				pUser->pED->AchivSystem.DeathMatch = 0;
									if(m_Achiv[n].data.ConditionLastTeamStanding > 0)		pUser->pED->AchivSystem.LastTeamStanding = 0;
									if(m_Achiv[n].data.ConditionDestroyTheBase > 0)			pUser->pED->AchivSystem.DestroyTheBase = 0;
									if(m_Achiv[n].data.ConditionCaptureTheFlag > 0)			pUser->pED->AchivSystem.CaptureTheFlag = 0;
									if(m_Achiv[n].data.ConditionSavesCaptureTheFlag > 0)	pUser->pED->AchivSystem.SavesCaptureTheFlag = 0;
									if(m_Achiv[n].data.ConditionVote > 0)					pUser->pED->AchivSystem.Vote = 0;
									if(m_Achiv[n].data.ConditionPvP > 0)					pUser->pED->AchivSystem.PvP = 0;
									if(m_Achiv[n].data.ConditionPk > 0)						pUser->pED->AchivSystem.Pk = 0;
									if(m_Achiv[n].data.ConditionHero > 0)					pUser->pED->AchivSystem.Hero = 0;
								
								}

								{
									for(UINT i=0;i<m_Achiv[n].data.ListConditionBoss.size();i++)
									{
										INT32 NpcId = m_Achiv[n].data.ListConditionBoss[i].NpcId;
										INT32 Counts = m_Achiv[n].data.ListConditionBoss[i].Counts;

										std::map<INT32, INT32>::iterator j(pUser->pED->AchivSystem.KillMobCounts.find(NpcId));
										if (j != pUser->pED->AchivSystem.KillMobCounts.end()) 
										{
											j->second = 0;
										}
									}
								}

								{
									for(UINT i=0;i<m_Achiv[n].data.ListConditionMob.size();i++)
									{
										INT32 NpcId = m_Achiv[n].data.ListConditionMob[i].NpcId;
										INT32 Counts = m_Achiv[n].data.ListConditionMob[i].Counts;

										std::map<INT32, INT32>::iterator j(pUser->pED->AchivSystem.KillMobCounts.find(NpcId));
										if (j != pUser->pED->AchivSystem.KillMobCounts.end()) 
										{
											j->second = 0;
										}
									}
								}

								std::wstringstream wss;
								wss << "El achivment " << m_Achiv[n].name_message  << "se ha reiniciado.";
								wstring mensaje = wss.str();
								pUser->SendSystemMessageRed(mensaje.c_str());

								Iter->second = ENUM_ENPROCESO;
								pUser->pED->AchivSystem.Save = true;
							}
						}
					}

			}


			if(pUser->pED->AchivSystem.Save)
			{
				Save(pUser);
			}
		}
	}

}


void Achivments::OnEnterWorld(User* pUser)	//OK
{
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);
		DB_GetCharacterData(pUser);
	}
}


void Achivments::DB_GetCharacterData(User* pUser)		//OK
{
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);
		g_DB.Send("chd", 0xF9, CI_REQUEST_LOAD_ACHIVMENTS, pUser->nDBID);
	}
}

bool Achivments::DB_GetCharacterDataReceived_1(CDBSocket *pSocket, const unsigned char* packet, UINT packetId)
{
	guard;

	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		int charId=0, AchivCounts=0;
		packet = Disassemble(packet, "dd", &charId, &AchivCounts);

		for (int i=0; i<AchivCounts; i++) 
		{
			int AchivId;
			int AchivState;
			int time;

			packet = Disassemble(packet, "ddd", &AchivId, &AchivState, &time);

			if(User *pUser = g_UserDB.GetUserByDBID(charId))
			{
				{
					std::map<INT32, AchivEstadoUser>::iterator i(pUser->pED->AchivSystem.ListAchivState.find(AchivId));
					if (i == pUser->pED->AchivSystem.ListAchivState.end()) 
						pUser->pED->AchivSystem.ListAchivState.insert(pair<INT32, AchivEstadoUser>(AchivId, (AchivEstadoUser)AchivState));
					else 
					{
						i->second = (AchivEstadoUser)AchivState;
					}
				}

				{
					std::map<INT32, INT32>::iterator i(pUser->pED->AchivSystem.ListAchivTime.find(AchivId));
					if (i == pUser->pED->AchivSystem.ListAchivTime.end()) 
						pUser->pED->AchivSystem.ListAchivTime.insert(pair<INT32, INT32>(AchivId, time));
					else 
					{
						i->second = time;
					}
				}
			}
		}
	}

	unguard;
	return false;
}

bool Achivments::DB_GetCharacterDataReceived_2(CDBSocket *pSocket, const unsigned char* packet, UINT packetId)	//OK
{
	guard;

	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		UINT charId = 0;
		INT32 Olympiad = 0, DeathMatch = 0, LastTeamStanding = 0, DestroyTheBase = 0, CaptureTheFlag = 0, SavesCaptureTheFlag = 0, 
			Vote = 0, PvP = 0, Pk = 0, Login = 0, Hero = 0;
		Disassemble(packet, "dddddddddddd", &charId, &Olympiad, &DeathMatch, &LastTeamStanding, &DestroyTheBase, &CaptureTheFlag, &SavesCaptureTheFlag, &PvP, &Pk, &Hero, &Login, &Vote);


		if(User *pUser = g_UserDB.GetUserByDBID(charId))
		{
			pUser->pED->AchivSystem.Olympiad = Olympiad;
			pUser->pED->AchivSystem.DeathMatch = DeathMatch;
			pUser->pED->AchivSystem.LastTeamStanding = LastTeamStanding;
			pUser->pED->AchivSystem.DestroyTheBase = DestroyTheBase;
			pUser->pED->AchivSystem.CaptureTheFlag = CaptureTheFlag;
			pUser->pED->AchivSystem.SavesCaptureTheFlag = SavesCaptureTheFlag;
			pUser->pED->AchivSystem.PvP = PvP;
			pUser->pED->AchivSystem.Pk = Pk;
			pUser->pED->AchivSystem.Hero = Hero;
			pUser->pED->AchivSystem.Login = Login;
			pUser->pED->AchivSystem.Vote = Vote;
		}
	}

	unguard;
	return false;
}

bool Achivments::DB_GetCharacterDataReceived_3(CDBSocket *pSocket, const unsigned char* packet, UINT packetId)
{
//	NPCS,
	guard;

	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		int charId=0, NpcCounts=0;
		packet = Disassemble(packet, "dd", &charId, &NpcCounts);

		for (int i=0; i<NpcCounts; i++) 
		{
			int npcId;
			int count;

			packet = Disassemble(packet, "dd", &npcId, &count);

			if(User *pUser = g_UserDB.GetUserByDBID(charId))
			{
				std::map<INT32, INT32>::iterator i(pUser->pED->AchivSystem.KillMobCounts.find(npcId));
				if (i == pUser->pED->AchivSystem.KillMobCounts.end()) 
					pUser->pED->AchivSystem.KillMobCounts.insert(pair<INT32, INT32>(npcId, count));
				else 
				{
					i->second = count;
				}
			}
		}
	}

	unguard;
	return false;
}


void Achivments::DB_GetHWIDs()
{
	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		g_DB.Send("ch", 0xF9, CI_REQUEST_LOAD_ACHIVMENTS_HWIDS);
	}
}

bool Achivments::DB_GetHWIDsReceived(CDBSocket *pSocket, const unsigned char* packet, UINT packetId)
{
	guard;

	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		int hwid_count;
		packet = Disassemble(packet, "d", &hwid_count);

		int AchivId;
		BYTE hwid[32];
		int time;
		for (int i=0; i<hwid_count; i++) {
			packet = Disassemble(packet, "ddb", &AchivId, &time, 32, hwid);

			AchivHWID tmp_AchivHwid;
			tmp_AchivHwid.AchivId = AchivId;
			memcpy(tmp_AchivHwid.hwid, hwid, 32);
			tmp_AchivHwid.time = time;
			HWIDs.push_back(tmp_AchivHwid);		
		}
	}

	unguard;
	return false;
}

/*
void Achivments::DB_SaveHWIDs()
{
	guard;

	CHAR Buff[8192];
	int nLen = 0;
	nLen += Assemble(Buff, (8192-nLen), "chd", 0xF9, CI_REQUEST_SAVE_ACHIVMENTS_HWIDS, (int)HWIDs.size());

	for (int i=0; i<HWIDs.size(); i++) {
		nLen += Assemble(&Buff[nLen], (8192-nLen), "ddb", HWIDs[i].AchivId, HWIDs[i].time, 32, HWIDs[i].hwid );
	}

	g_DB.Send("b", nLen, Buff);

	unguard;
}*/

void Achivments::DB_SaveHWIDs()
{
    guard;

	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		const int MaxPacketSize = 8192;  // Tamaño máximo del paquete
		const int MaxRecordsPerPacket = 100;  // Número máximo de registros por paquete

		int totalRecords = HWIDs.size();
		int numPackets = (totalRecords + MaxRecordsPerPacket - 1) / MaxRecordsPerPacket;  // Calcula el número de paquetes

		for (int packetIndex = 0; packetIndex < numPackets; ++packetIndex) {
			CHAR Buff[MaxPacketSize];
			int nLen = 0;
			int startRecordIndex = packetIndex * MaxRecordsPerPacket;
			int recordsInPacket = min(MaxRecordsPerPacket, totalRecords - startRecordIndex);

			// Construir el paquete
			nLen += Assemble(Buff, (MaxPacketSize - nLen), "chd", 0xF9, CI_REQUEST_SAVE_ACHIVMENTS_HWIDS, recordsInPacket);

			for (int i = startRecordIndex; i < startRecordIndex + recordsInPacket; ++i) {
				nLen += Assemble(&Buff[nLen], (MaxPacketSize - nLen), "ddb", HWIDs[i].AchivId, HWIDs[i].time, 32, HWIDs[i].hwid);
			}

			g_DB.Send("b", nLen, Buff);
		}
	}

    unguard;
}


void Achivments::DB_SaveCharacterData_1(User* pUser)
{
	guard;

	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		CHAR Buff[8192];
		int nLen = 0;
		nLen += Assemble(Buff, (8192-nLen), "chdd", 0xF9, CI_REQUEST_SAVE_ACHIVMENTS_1, pUser->nDBID, (int)pUser->pED->AchivSystem.ListAchivState.size());

		for(std::map<INT32, AchivEstadoUser>::iterator Iter=pUser->pED->AchivSystem.ListAchivState.begin();Iter!=pUser->pED->AchivSystem.ListAchivState.end();Iter++)
		{
			int time = 0;
			int achivId = Iter->first;
			int state = (int)Iter->second;

			std::map<INT32, INT32>::iterator i(pUser->pED->AchivSystem.ListAchivTime.find(achivId));
			if (i != pUser->pED->AchivSystem.ListAchivTime.end()) 
			{
				time = i->second;
			}

			nLen += Assemble(&Buff[nLen], (8192-nLen), "ddd", achivId, state,time);
		}

		g_DB.Send("b", nLen, Buff);
	}
	unguard;
}

void Achivments::DB_SaveCharacterData_2(User* pUser)		//OK
{
	guard;

	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		int char_id = pUser->nDBID;
		int Olympiad = pUser->pED->AchivSystem.Olympiad;
		int DeathMatch = pUser->pED->AchivSystem.DeathMatch;
		int LastTeamStanding = pUser->pED->AchivSystem.LastTeamStanding;
		int DestroyTheBase = pUser->pED->AchivSystem.DestroyTheBase;
		int CaptureTheFlag = pUser->pED->AchivSystem.CaptureTheFlag;
		int SavesCaptureTheFlag = pUser->pED->AchivSystem.SavesCaptureTheFlag;
		int PvP = pUser->pED->AchivSystem.PvP;
		int Pk = pUser->pED->AchivSystem.Pk;
		int Hero = pUser->pED->AchivSystem.Hero;
		int Login = pUser->pED->AchivSystem.Login;
		int Vote = pUser->pED->AchivSystem.Vote;

		g_DB.Send("chdddddddddddd", 0xF9, CI_REQUEST_SAVE_ACHIVMENTS_2, char_id, Olympiad, DeathMatch, LastTeamStanding, DestroyTheBase, CaptureTheFlag, SavesCaptureTheFlag, PvP, Pk, Hero, Login, Vote);
	}
	unguard;
}


void Achivments::DB_SaveCharacterData_3(User* pUser)
{
	guard;

	if(g_achiv)
	{
		g_Log.Add(CLog::Error, "[%s]", __FUNCTION__);

		CHAR Buff[8192];
		int nLen = 0;
		nLen += Assemble(Buff, (8192-nLen), "chdd", 0xF9, CI_REQUEST_SAVE_ACHIVMENTS_3, pUser->nDBID, (int)pUser->pED->AchivSystem.KillMobCounts.size());

		for(std::map<INT32, INT32>::iterator Iter=pUser->pED->AchivSystem.KillMobCounts.begin();Iter!=pUser->pED->AchivSystem.KillMobCounts.end();Iter++)
		{
			int NpcId = Iter->first;
			int Count = Iter->second;

			nLen += Assemble(&Buff[nLen], (8192-nLen), "dd", NpcId, Count);
		}

		g_DB.Send("b", nLen, Buff);
	}
	unguard;
}