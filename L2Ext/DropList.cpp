#include "stdafx.h"
#include "DropList.h"
#include "AutoLoot.h"
#include "VipSystem.h"
#include "DnN.h"
#include "ObjectDB.h"
#include "HappyHours.h"
#include "ChampionNpc.h"
#include "SkillAcquireDB.h"
#include "HtmlCache.h"
#include "PlayerAction.h"
#include "NpcDb.h"
#include "TvT.h"
#include "DropRaidsCustom.h"
#include "Achivments.h"
#include "RatesDinamicos.h"

using namespace NpcData;

extern DOUBLE* g_lpDropRate;

extern DOUBLE* g_lpSpoilRate;

extern BOOL g_CambiarIDSealStones;

extern BOOL g_RecargaEnProceso;


extern INT32 customDrop_delay;

vector<INT32> blockedDropItems;

CDropList g_DropList;

CDropList::CDropList() : m_enabled(FALSE), m_debugMsg(FALSE), m_raidBossItemRate(1.0)
{
}

CDropList::~CDropList()
{
//	Release();
}

void CDropList::Release()
{
	for(map<INT32, NpcDropInfo*>::iterator it = m_data.begin(); it!= m_data.end(); it++)
	{
		if(it->second)
		{
			delete it->second;
			it->second = 0;
		}
	}
	m_data.clear();
	m_dataHtml.clear();
	m_dataHtmlSpoil.clear();
}

void CDropList::Init()
{
	Release();
	m_enabled = FALSE;
	m_raidBossItemRate = 1.0;
	m_SpellbooksDrop = FALSE;
	ItemsNotDroppedLoad();
	LoadData();
	if(m_enabled)
	{
		g_Log.Add(CLog::Blue, "[Drop List] Feature is enabled. Loaded [%d] npcs.", m_data.size());
	}

}

void CDropList::LoadData()
{
	g_RecargaEnProceso = true;

	const TCHAR* section = _T("DropList");

	m_enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);
	m_enabledShift = GetPrivateProfileInt(section, _T("EnabledShift"), 0, g_ConfigFile);
	m_debugMsg = GetPrivateProfileInt(section, _T("DebugMsg"), 0, g_ConfigFile);
	m_SpellbooksDrop = GetPrivateProfileInt(section, _T("SpellbooksDropBlock"), 0, g_ConfigFile);

	double temp = GetPrivateProfileDouble(section, _T("RaidBossItemRate"), 100.0, g_ConfigFile);
	temp /= 100.0;
	m_raidBossItemRate = temp;


	double temp3 = GetPrivateProfileDouble(section, _T("ItemCountsRate"), 100.0, g_ConfigFile);
	temp3 /= 100.0;
	m_ItemCountsRate = temp3;

	double temp4 = GetPrivateProfileDouble(section, _T("SpoilCountsRate"), 100.0, g_ConfigFile);
	temp4 /= 100.0;
	m_SpoilCountsRate = temp4;


	double temp2 = GetPrivateProfileDouble(section, _T("SealStoneRateQuanity"), 100.0, g_ConfigFile);
	temp2 /= 100.0;
	m_SealStoneRate = temp2;


	m_raidBossItemRate *= g_RatesDinamicos.GetRaidBossItemChance();
	m_ItemCountsRate *= g_RatesDinamicos.GetItemCountsChance();
	m_SpoilCountsRate *= g_RatesDinamicos.GetSpoilCount();
	m_SealStoneRate *= g_RatesDinamicos.GetAncientAdenaRate();


	if(true /*m_enabled*/)
	{
		wstringstream npcDataStream(ReadFileW(g_ChangeFolders.NpcData_txt));
		wstring line;
		while(getline(npcDataStream, line))
		{
			ParseNpcData(line);
		}
	}

	blockedDropItems.clear();

	TCHAR sTemp[0x8000];
	if(GetPrivateProfileString(_T("DropList"), _T("BlockedDropItems"), 0, sTemp, 0x8000, g_ConfigFile))
	{
		tstringstream sstr;
		sstr << sTemp;
		INT32 itemId = 0;
		while(sstr >> itemId)
		{
			blockedDropItems.push_back(itemId);
		}
	}






	g_RecargaEnProceso = false;
}

void CDropList::ParseNpcData(std::wstring line)
{
	guard;
	if(true /*m_enabled*/)
	{
		//npc_begin	warrior	20446	[utuku_orc]	level=6	acquire_exp_rate=5.9167	acquire_sp=6	unsowing=0	clan={@orc_clan}	ignore_clan_list={}	clan_help_range=300	slot_chest=[]	slot_rhand=[hand_axe]	slot_lhand=[]	shield_defense_rate=0	shield_defense=0	skill_list={@s_race_humanoids}	npc_ai={[utuku_orc];{[MoveAroundSocial]=138};{[MoveAroundSocial1]=138};{[MoveAroundSocial2]=138}}	category={}	race=humanoid	sex=male	undying=0	can_be_attacked=1	corpse_time=7	no_sleep_mode=0	agro_range=1000	ground_high={110;0;0}	ground_low={45;0;0}	exp=6039	org_hp=93.54158	org_hp_regen=2	org_mp=77.2	org_mp_regen=0.9	collision_radius={10;10}	collision_height={21;21}	str=40	int=21	dex=30	wit=20	con=43	men=20	base_attack_type=blunt	base_attack_range=40	base_damage_range={0;0;80;120}	base_rand_dam=50	base_physical_attack=13.52471	base_critical=1	physical_hit_modify=9	base_attack_speed=253	base_reuse_delay=0	base_magic_attack=9.23562	base_defend=53.53373	base_magic_defend=35.6433609604933	physical_avoid_modify=0	soulshot_count=0	spiritshot_count=0	hit_time_factor=0.48	item_make_list={}	corpse_make_list={{[iron_ore];1;1;7.7741};{[coal];1;1;7.7741};{[bow_shaft];1;1;0.5553}}	additional_make_list={}	additional_make_multi_list={{{{[adena];41;58;100}};70};{{{[leather_shirt];1;1;38.4772};{[leather_pants];1;1;61.5228}};0.4912};{{{[rp_brandish];1;1;5.80429};{[stem];1;1;62.7971};{[iron_ore];1;1;31.3986}};4.8757}}	hp_increase=0	mp_increase=0	safe_height=100	npc_end
		if(line.find(L"npc_begin") == 0)
		{
			//normalize line - anti stupid/lazy ppl
			line = Utils::ReplaceStringW(line, L" ", L"\t", true);
			line = Utils::ReplaceStringW(line, L"\t\t", L"\t", true);
			line = Utils::ReplaceStringW(line, L"\t=", L"=", true);
			line = Utils::ReplaceStringW(line, L"=\t", L"=", true);
			
			vector<wstring> column;
			wstringstream lineStream(line);
			wstring col;
			while(getline(lineStream, col, L'\t'))
			{
				column.push_back(col);
			}
			if(column.size() > 5)
			{
				INT32 npcId = 1000000 + _wtoi(column[2].c_str());
				if(npcId > 1000000)
				{
				//	g_Log.Add(CLog::Blue, "[%s] Npc[%d] [%S]", __FUNCTION__, npcId, column[2].c_str());
					NpcDropInfo *pInfo = new NpcDropInfo;
					if(pInfo)
					{
						pInfo->classId = npcId;
						for(int n=0;n<column.size();n++)
						{
							wstring parseLine = column[n];
							if(parseLine.find(L"corpse_make_list=") == 0)
							{
								wstring data = parseLine.substr(17, (parseLine.size() - 17) );
								if(ParseAdditionalMakeList2(pInfo->SpoilListFull, data))
								{
									continue;
								}else
								{
									g_Log.Add(CLog::Error, "[%d] Error while parsing corpse_make_list for npc[%d]!", __FUNCTION__, npcId); 
								}
							}
							else if(parseLine.find(L"item_make_list=") == 0)
							{
								wstring data = parseLine.substr(15, (parseLine.size() - 15) );
								if(ParseItemMakeList(pInfo->itemMakeList, data))
								{
									ParseAdditionalMakeList2(pInfo->DropListFull, data);
									continue;
								}else
								{
									g_Log.Add(CLog::Error, "[%d] Error while parsing item_make_list for npc[%d]!", __FUNCTION__, npcId); 
								}
							}
							else if(parseLine.find(L"additional_make_list=") == 0)
							{
								wstring data = parseLine.substr(21, (parseLine.size() - 21) );
								if(ParseAdditionalMakeList(pInfo->additionalMakeList, data))
								{
									ParseAdditionalMakeMultiList2(pInfo->DropListFull, data, false);
									continue;
								}else
								{
									g_Log.Add(CLog::Error, "[%d] Error while parsing additional_make_list for npc[%d]!", __FUNCTION__, npcId); 
								}
							}
							else if(parseLine.find(L"additional_make_multi_list=") == 0)
							{
								wstring data = parseLine.substr(27, (parseLine.size() - 27) );
								if(ParseAdditionalMakeMultiList(pInfo->additionalMakeMultiList, data))
								{

									bool IsBoss = false;

									if (column[1] == L"boss")
										IsBoss=true;


									ParseAdditionalMakeMultiList2(pInfo->DropListFull, data, IsBoss);
									continue;
								}else
								{
									g_Log.Add(CLog::Error, "[%d] Error while parsing additional_make_multi_list for npc[%d]!", __FUNCTION__, npcId); 
								}
							}
						}
						m_data.insert(pair<INT32, NpcDropInfo*>(npcId, pInfo));
	
						if( (pInfo->additionalMakeList.size() > 0) || (pInfo->additionalMakeMultiList.size() > 0) || (pInfo->itemMakeList.size() > 0) )
						{
									bool IsBoss = false;

									if (column[1] == L"boss")
									{
									//	g_Log.Add(CLog::Error, "1111111111111111111"); 
										IsBoss=true;
									}


							CreateHtmlDroplist(npcId, IsBoss);
							//g_Log.Add(CLog::Error, "[%d] Added npc[%d]!", __FUNCTION__, npcId); 
						}
					}else
					{
						AddToCallStack(L"Cannot allocate memory for NpcDropInfo!");
						LPDWORD lpCrash = 0;
						(*lpCrash) = 0x666;
					}
				}
			}
		}
	}
	unguard;
}

bool CDropList::ParseItemMakeList(std::vector<ItemDropInfo> &itemMakeList, std::wstring data)
{
	guard;
	if(data.size() > 3)
	{
		//additional_make_list=
		//{{[breaking_arrow];50;100;100}}
		data = Utils::ReplaceStringW(data, L"{", L" ", true);
		data = Utils::ReplaceStringW(data, L"}", L" ", true);
		data = Utils::ReplaceStringW(data, L";", L" ", true);
		data = Utils::ReplaceStringW(data, L"]", L" ", true);
		data = Utils::ReplaceStringW(data, L"[", L" ", true);
		//  [breaking_arrow] 50 100 100  
		wstringstream dataStream(data);
		ItemDropInfo idi = { 0, 0, 0, 0, 0, 0 };
		wstring itemName;
		while(dataStream >> itemName >> idi.minCount >> idi.maxCount >> idi.chance)
		{
			if(itemName.size() > 0)
			{
				idi.itemId = g_ObjectDB.GetClassIdFromName(itemName.c_str());
				if(idi.itemId)
				{


							CItem *pItem = g_ObjectDB.GetTemplateObject(idi.itemId)->SafeCastItem();
							//CItem *pItem = CObject::GetObjectBySID(idi.itemId)->SafeCastItem();
							if(pItem)
							{
								if (pItem->pSID->nConsumeType == 2)
									idi.stackable =true;
							}


							INT32 item_min = idi.minCount;
							INT32 item_max = idi.maxCount;

							if(idi.stackable && idi.itemId != 57 && idi.itemId != 6360 && idi.itemId != 6361 && idi.itemId != 6362)
							{
								if (m_ItemCountsRate>1)
								{
									double newCountMin = static_cast<double>(item_min);
									newCountMin *= m_ItemCountsRate;
									item_min = static_cast<INT32>(newCountMin);

									double newCountMax = static_cast<double>(item_max);
									newCountMax *= m_ItemCountsRate;
									item_max = static_cast<INT32>(newCountMax);
								}
							}
							else if(idi.itemId == 57)
							{
								DOUBLE* lpAdenaRate2 = (DOUBLE*)0xBEF260;
								double adenaRate = (*lpAdenaRate2);
								adenaRate *= g_RatesDinamicos.GetAdenaRate();

								double newCountMin = static_cast<double>(item_min);
								newCountMin *= adenaRate;
								item_min = static_cast<INT32>(newCountMin);

								double newCountMax = static_cast<double>(item_max);
								newCountMax *= adenaRate;
								item_max = static_cast<INT32>(newCountMax);
							}
							else if( idi.itemId == 6360 || idi.itemId == 6361 || idi.itemId == 6362)
							{
								double newCountMin = static_cast<double>(item_min);
								newCountMin *= m_SealStoneRate;
								item_min = static_cast<INT32>(newCountMin);

								double newCountMax = static_cast<double>(item_max);
								newCountMax *= m_SealStoneRate;
								item_max = static_cast<INT32>(newCountMax);
							}

							idi.minCount = item_min;
							idi.maxCount = item_max;


					if(m_SpellbooksDrop)
					{
						if(!g_SkillAcquireDB.ItemForNotDrop(idi.itemId) && !ItemForNotDrop(idi.itemId))
							itemMakeList.push_back(idi);
					}
					else
					{
						if(!ItemForNotDrop(idi.itemId))
							itemMakeList.push_back(idi);
					}
				}
			}
		}
	}
	unguard;
	return true;
}

bool CDropList::ParseAdditionalMakeList(vector<ItemDropInfo>& additionalMakeList, wstring data)
{
	guard;
	//additional_make_list=
	//{{[breaking_arrow];50;100;100}}
	if(data.size() > 3)
	{
		data = Utils::ReplaceStringW(data, L"{", L" ", true);
		data = Utils::ReplaceStringW(data, L"}", L" ", true);
		data = Utils::ReplaceStringW(data, L";", L" ", true);
		data = Utils::ReplaceStringW(data, L"]", L" ", true);
		data = Utils::ReplaceStringW(data, L"[", L" ", true);
		//  [breaking_arrow] 50 100 100  
		wstringstream dataStream(data);
		ItemDropInfo idi = { 0, 0, 0, 0, 0, 0 };
		wstring itemName;
		while(dataStream >> itemName >> idi.minCount >> idi.maxCount >> idi.chance)
		{
			if(itemName.size() > 0)
			{
				idi.itemId = g_ObjectDB.GetClassIdFromName(itemName.c_str());
				if(idi.itemId)
				{
					if(m_SpellbooksDrop)
					{
						if(!g_SkillAcquireDB.ItemForNotDrop(idi.itemId) && !ItemForNotDrop(idi.itemId))
							additionalMakeList.push_back(idi);
					}
					else
					{
						if(!ItemForNotDrop(idi.itemId))
							additionalMakeList.push_back(idi);
					}
				}
			}
		}
	}

	unguard;
	return true;
}

bool CDropList::ParseAdditionalMakeList2(vector<ItemDropInfo>& additionalMakeList, wstring data)
{
	guard;
	//additional_make_list=
	//{{[breaking_arrow];50;100;100}}
	if(data.size() > 3)
	{
		data = Utils::ReplaceStringW(data, L"{", L" ", true);
		data = Utils::ReplaceStringW(data, L"}", L" ", true);
		data = Utils::ReplaceStringW(data, L";", L" ", true);
		data = Utils::ReplaceStringW(data, L"]", L" ", true);
		data = Utils::ReplaceStringW(data, L"[", L" ", true);
		//  [breaking_arrow] 50 100 100  
		wstringstream dataStream(data);
		ItemDropInfo idi = { 0, 0, 0, 0, 0, 0 };
		wstring itemName;
		while(dataStream >> itemName >> idi.minCount >> idi.maxCount >> idi.chance)
		{
			if(itemName.size() > 0)
			{
				idi.itemId = g_ObjectDB.GetClassIdFromName(itemName.c_str());
				if(idi.itemId)
				{
							CItem *pItem = g_ObjectDB.GetTemplateObject(idi.itemId)->SafeCastItem();
							//CItem *pItem = CObject::GetObjectBySID(idi.itemId)->SafeCastItem();
							if(pItem)
							{
								if (pItem->pSID->nConsumeType == 2)
									idi.stackable =true;
							}

							INT32 item_min = idi.minCount;
							INT32 item_max = idi.maxCount;

							if(idi.stackable && idi.itemId != 57 && idi.itemId != 6360 && idi.itemId != 6361 && idi.itemId != 6362)
							{
								if (m_SpoilCountsRate>1)
								{
									double newCountMin = static_cast<double>(item_min);
									newCountMin *= m_SpoilCountsRate;
									item_min = static_cast<INT32>(newCountMin);

									double newCountMax = static_cast<double>(item_max);
									newCountMax *= m_SpoilCountsRate;
									item_max = static_cast<INT32>(newCountMax);
								}
							}
							else if(idi.itemId == 57)
							{
								DOUBLE* lpAdenaRate2 = (DOUBLE*)0xBEF260;
								double adenaRate = (*lpAdenaRate2);
								adenaRate *= g_RatesDinamicos.GetAdenaRate();

								double newCountMin = static_cast<double>(item_min);
								newCountMin *= adenaRate;
								item_min = static_cast<INT32>(newCountMin);

								double newCountMax = static_cast<double>(item_max);
								newCountMax *= adenaRate;
								item_max = static_cast<INT32>(newCountMax);
							}
							else if( idi.itemId == 6360 || idi.itemId == 6361 || idi.itemId == 6362)
							{
								double newCountMin = static_cast<double>(item_min);
								newCountMin *= m_SealStoneRate;
								item_min = static_cast<INT32>(newCountMin);

								double newCountMax = static_cast<double>(item_max);
								newCountMax *= m_SealStoneRate;
								item_max = static_cast<INT32>(newCountMax);
							}

							idi.minCount = item_min;
							idi.maxCount = item_max;

							double dropRate = (*g_lpSpoilRate);
							idi.chance *= dropRate;
							idi.chance *= g_RatesDinamicos.GetSpoilRate();





					if(m_SpellbooksDrop)
					{
						if(!g_SkillAcquireDB.ItemForNotDrop(idi.itemId) && !ItemForNotDrop(idi.itemId))
							additionalMakeList.push_back(idi);
					}
					else
					{
						if(!ItemForNotDrop(idi.itemId))
							additionalMakeList.push_back(idi);
					}

					//additionalMakeList.push_back(idi);
				}
			}
		}
	}

	unguard;
	return true;
}

bool CDropList::ParseAdditionalMakeMultiList(vector<GroupDropInfo>& additionalMakeMultiList, wstring data)
{
	guard;
	//additional_make_multi_list=
	//{{{{[adena];30;42;100}};70};{{{[apprentice_s_earing];1;1;30.9858};{[magic_ring];1;1;46.0093};{[necklace_of_magic];1;1;23.0049}};25.7011}}
	if(data.size() > 3)
	{
		data = data.substr(1, data.size() - 2);

		//split data into groups
		size_t pos = data.find(L";{{{");
		while(pos != wstring::npos)
		{
			data = data.replace(pos, 1, L" ");
			pos = data.find(L";{{{");
		}

		wstringstream dataStream(data);
		wstring group;
		while(dataStream >> group)
		{
			if(group.size() > 3)
			{
				//{{{[magic_ring];1;1;46.0093};{[necklace_of_magic];1;1;23.0049}};25.7011}
				GroupDropInfo gdi;
				gdi.chance = 0.0;
				gdi.itemsChanceSum = 0.0;
				gdi.adenaGroup = FALSE;

				group = group.substr(1, group.size() - 2);
				//{{[magic_ring];1;1;46.0093};{[necklace_of_magic];1;1;23.0049}};25.7011
				INT32 itemCount = 1;
				pos = group.find(L"};{");
				while(pos != wstring::npos)
				{
					itemCount++;
					pos = group.find(L"};{", pos + 1);
				}

				group = Utils::ReplaceStringW(group, L"{", L" ", true);
				group = Utils::ReplaceStringW(group, L"}", L" ", true);
				group = Utils::ReplaceStringW(group, L";", L" ", true);
				group = Utils::ReplaceStringW(group, L"]", L" ", true);
				group = Utils::ReplaceStringW(group, L"[", L" ", true);

				wstringstream itemStream(group);
				for(int n=0;n<itemCount;n++)
				{
					wstring itemName;
					ItemDropInfo idi = { 0, 0, 0, 0, 0, 0 };
					itemStream >> itemName >> idi.minCount >> idi.maxCount >> idi.chance;
					if(itemName.size() > 0)
					{
						idi.itemId = g_ObjectDB.GetClassIdFromName(itemName.c_str());
						if(idi.itemId > 0)
						{

							CItem *pItem = g_ObjectDB.GetTemplateObject(idi.itemId)->SafeCastItem();
							//CItem *pItem = CObject::GetObjectBySID(idi.itemId)->SafeCastItem();
							if(pItem)
							{
								if (pItem->pSID->nConsumeType == 2)
									idi.stackable =true;
							}

							if(idi.itemId == 57 || idi.itemId == 6360 || idi.itemId == 6361 || idi.itemId == 6362)
							{
								gdi.adenaGroup = TRUE;
							}
				//			g_Log.Add(CLog::Blue, "[%s] adding[%d][%d][%d][%f]", __FUNCTION__, idi.itemId, idi.minCount, idi.maxCount, idi.chance);
							gdi.itemsChanceSum += idi.chance;
							//gdi.items.push_back(idi);


							INT32 item_min = idi.minCount;
							INT32 item_max = idi.maxCount;

							if(idi.stackable && idi.itemId != 57 && idi.itemId != 6360 && idi.itemId != 6361 && idi.itemId != 6362)
							{
								if (m_ItemCountsRate>1)
								{
									double newCountMin = static_cast<double>(item_min);
									newCountMin *= m_ItemCountsRate;
									item_min = static_cast<INT32>(newCountMin);

									double newCountMax = static_cast<double>(item_max);
									newCountMax *= m_ItemCountsRate;
									item_max = static_cast<INT32>(newCountMax);
								}
							}
							else if(idi.itemId == 57)
							{
								DOUBLE* lpAdenaRate2 = (DOUBLE*)0xBEF260;
								double adenaRate = (*lpAdenaRate2);
								adenaRate *= g_RatesDinamicos.GetAdenaRate();

								double newCountMin = static_cast<double>(item_min);
								newCountMin *= adenaRate;
								item_min = static_cast<INT32>(newCountMin);

								double newCountMax = static_cast<double>(item_max);
								newCountMax *= adenaRate;
								item_max = static_cast<INT32>(newCountMax);
							}
							else if( idi.itemId == 6360 || idi.itemId == 6361 || idi.itemId == 6362)
							{
								double newCountMin = static_cast<double>(item_min);
								newCountMin *= m_SealStoneRate;
								item_min = static_cast<INT32>(newCountMin);

								double newCountMax = static_cast<double>(item_max);
								newCountMax *= m_SealStoneRate;
								item_max = static_cast<INT32>(newCountMax);
							}

							idi.minCount = item_min;
							idi.maxCount = item_max;

							if(m_SpellbooksDrop)
							{
								if(!g_SkillAcquireDB.ItemForNotDrop(idi.itemId) && !ItemForNotDrop(idi.itemId))
									gdi.items.push_back(idi);
							}
							else
							{
								if(!ItemForNotDrop(idi.itemId))
									gdi.items.push_back(idi);
							}
						}
					}
				}
				itemStream >> gdi.chance;
				if(gdi.chance > 0.0)
				{


					struct ItemDropInfo temporal;

					int x;
					for (x = 0; x < gdi.items.size(); x++)
					{
						int indiceActual;
						for (indiceActual = 0; indiceActual < gdi.items.size() - 1;
							 indiceActual++)
						{
							int indiceSiguienteElemento = indiceActual + 1;

							// Ordenar por chance, de manera ascendente--- cambiar < >
							if (gdi.items[indiceActual].chance > gdi.items[indiceSiguienteElemento].chance)
							{
								// Intercambiar
								memcpy(&temporal, &gdi.items[indiceActual], sizeof(struct ItemDropInfo));
								memcpy(&gdi.items[indiceActual], &gdi.items[indiceSiguienteElemento], sizeof(struct ItemDropInfo));
								memcpy(&gdi.items[indiceSiguienteElemento], &temporal, sizeof(struct ItemDropInfo));
							}
						}
					}





			//		g_Log.Add(CLog::Blue, "[%s] Adding group size[%d] chance[%f]", __FUNCTION__, gdi.items.size(), gdi.chance);
					additionalMakeMultiList.push_back(gdi);
				}else
				{
					g_Log.Add(CLog::Error, "[%s] Invalid group chance[%f]!", __FUNCTION__, gdi.chance);
					unguard;
					return false;
				}
			}
		}
	}

	unguard;
	return true;
}

bool CDropList::ParseAdditionalMakeMultiList2(vector<ItemDropInfo>& additionalMakeMultiList, wstring data, bool IsBoss)
{
	guard;
	//additional_make_multi_list=
	//{{{{[adena];30;42;100}};70};{{{[apprentice_s_earing];1;1;30.9858};{[magic_ring];1;1;46.0093};{[necklace_of_magic];1;1;23.0049}};25.7011}}
	if(data.size() > 3)
	{
		data = data.substr(1, data.size() - 2);

		//split data into groups
		size_t pos = data.find(L";{{{");
		while(pos != wstring::npos)
		{
			data = data.replace(pos, 1, L" ");
			pos = data.find(L";{{{");
		}

		int groupid= 1;
		wstringstream dataStream(data);
		wstring group;
		while(dataStream >> group)
		{
			if(group.size() > 3)
			{
				//{{{[magic_ring];1;1;46.0093};{[necklace_of_magic];1;1;23.0049}};25.7011}
				//GroupDropInfo gdi;
				//gdi.chance = 0.0;
				//gdi.itemsChanceSum = 0.0;
				//gdi.adenaGroup = FALSE;
				vector<ItemDropInfo> items;

				group = group.substr(1, group.size() - 2);
				//{{[magic_ring];1;1;46.0093};{[necklace_of_magic];1;1;23.0049}};25.7011
				INT32 itemCount = 1;
				pos = group.find(L"};{");
				while(pos != wstring::npos)
				{
					itemCount++;
					pos = group.find(L"};{", pos + 1);
				}

				group = Utils::ReplaceStringW(group, L"{", L" ", true);
				group = Utils::ReplaceStringW(group, L"}", L" ", true);
				group = Utils::ReplaceStringW(group, L";", L" ", true);
				group = Utils::ReplaceStringW(group, L"]", L" ", true);
				group = Utils::ReplaceStringW(group, L"[", L" ", true);

				wstringstream itemStream(group);
				for(int n=0;n<itemCount;n++)
				{
					wstring itemName;
					ItemDropInfo idi = { 0, 0, 0, 0, 0, 0 };
					itemStream >> itemName >> idi.minCount >> idi.maxCount >> idi.chance;
					if(itemName.size() > 0)
					{
						idi.itemId = g_ObjectDB.GetClassIdFromName(itemName.c_str());
						if(idi.itemId > 0)
						{

							if(m_SpellbooksDrop)
							{
								if(!g_SkillAcquireDB.ItemForNotDrop(idi.itemId) && !ItemForNotDrop(idi.itemId))
									items.push_back(idi);
							}
							else
							{
								if(!ItemForNotDrop(idi.itemId))
									items.push_back(idi);
							}
							//itemsChanceSum += idi.chance;
							//items.push_back(idi);
						}
					}
				}
				double GroupChance;
				itemStream >> GroupChance;
				if(GroupChance > 0.0)
				{
					for(int n=0;n<items.size();n++)
					{
						double ItemChance = items[n].chance;
						items[n].chance = ItemChance / (100.0/GroupChance);

						double dropRate = (*g_lpDropRate);


						if(IsBoss)
							dropRate = m_raidBossItemRate;

						//items[n].chance = items[n].chance * dropRate;
						

						CItem *pItem = g_ObjectDB.GetTemplateObject(items[n].itemId)->SafeCastItem();
						//CItem *pItem = CObject::GetObjectBySID(idi.itemId)->SafeCastItem();
						if(pItem)
						{
							if (pItem->pSID->nConsumeType == 2)
								items[n].stackable =true;
						}


							INT32 item_min = items[n].minCount;
							INT32 item_max = items[n].maxCount;

							if(items[n].stackable && items[n].itemId != 57 && items[n].itemId != 6360 && items[n].itemId != 6361 && items[n].itemId != 6362)
							{
								if (m_ItemCountsRate>1)
								{
									double newCountMin = static_cast<double>(item_min);
									newCountMin *= m_ItemCountsRate;
									item_min = static_cast<INT32>(newCountMin);

									double newCountMax = static_cast<double>(item_max);
									newCountMax *= m_ItemCountsRate;
									item_max = static_cast<INT32>(newCountMax);
								}
							}
							else if(items[n].itemId == 57)
							{
								DOUBLE* lpAdenaRate2 = (DOUBLE*)0xBEF260;
								double adenaRate = (*lpAdenaRate2);
								adenaRate *= g_RatesDinamicos.GetAdenaRate();

								double newCountMin = static_cast<double>(item_min);
								newCountMin *= adenaRate;
								item_min = static_cast<INT32>(newCountMin);

								double newCountMax = static_cast<double>(item_max);
								newCountMax *= adenaRate;
								item_max = static_cast<INT32>(newCountMax);
							}
							else if( items[n].itemId == 6360 || items[n].itemId == 6361 || items[n].itemId == 6362)
							{
								double newCountMin = static_cast<double>(item_min);
								newCountMin *= m_SealStoneRate;
								item_min = static_cast<INT32>(newCountMin);

								double newCountMax = static_cast<double>(item_max);
								newCountMax *= m_SealStoneRate;
								item_max = static_cast<INT32>(newCountMax);
							}


							items[n].minCount = item_min;
							items[n].maxCount = item_max;

							items[n].groupId = groupid;


						additionalMakeMultiList.push_back(items[n]);
					}

					//additionalMakeMultiList.push_back(gdi);
				}else
				{
					g_Log.Add(CLog::Error, "[%s] Invalid group chance[%f] - for droplist html!", __FUNCTION__, GroupChance);
					unguard;
					return false;
				}
			}
			groupid++;
		}
	}

	unguard;
	return true;
}

bool CDropList::ExistDroplist(UINT NpcId)
{
	guard;
	map<INT32, DropListHtml*>::iterator it = m_dataHtml.find(NpcId);
	if(it!=m_dataHtml.end())
		return true;
	else
		return false;

	unguard;
	return false;
}

void CDropList::ShowDroplist(User *pUser, UINT NpcId, UINT page)
{
	guard;

	wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...</center></body></html>";
	map<INT32, DropListHtml*>::iterator it = m_dataHtml.find(NpcId);
	if(it!=m_dataHtml.end())
	{
		DropListHtml* pInfo = it->second;
		if( (pInfo->m_Pages.size() > 0) && (page < pInfo->m_Pages.size()) )
		{
			html = pInfo->m_Pages[page];

			PlayerAction::ShowHTML(pUser, L"npc_drop_info.htm", html.c_str(), 0);
		}
	}
	else
	{
		html = g_HtmlCache.Get(L"npc_drop_info_not.htm");
		PlayerAction::ShowHTML(pUser, L"npc_drop_info_not.htm", html.c_str(), 0);

		//g_Log.Add(CLog::Error, "[%s] Debug[%d] Debug2[%d]!", __FUNCTION__, NpcId, page);
	}

	unguard;
}

void CDropList::ShowSpoilDroplist(User *pUser, UINT NpcId, UINT page)
{
	guard;

	wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...</center></body></html>";
	map<INT32, DropListHtml*>::iterator it = m_dataHtmlSpoil.find(NpcId);
	if(it!=m_dataHtmlSpoil.end())
	{
		DropListHtml* pInfo = it->second;
		if( (pInfo->m_Pages.size() > 0) && (page < pInfo->m_Pages.size()) )
		{
			html = pInfo->m_Pages[page];

			PlayerAction::ShowHTML(pUser, L"npc_spoil_info.htm", html.c_str(), 0);
		}
	}
	else
	{
		html = g_HtmlCache.Get(L"npc_spoil_info_not.htm");
		PlayerAction::ShowHTML(pUser, L"npc_spoil_info_not.htm", html.c_str(), 0);

		//g_Log.Add(CLog::Error, "[%s] Debug[%d] Debug2[%d]!", __FUNCTION__, NpcId, page);
	}

	unguard;
}

void CDropList::CreateHtmlDroplist(UINT NpcId, bool isBoss)
{
	guard;

	map<INT32, NpcDropInfo*>::iterator it = m_data.find(NpcId);
	if(it!=m_data.end())
	{
		NpcDropInfo* pInfo = it->second;

		//Spoil
		const WCHAR* wHTML = g_HtmlCache.Get(L"npc_spoil_info.htm");
		if(wHTML)
		{
			if(pInfo->SpoilListFull.size() > 0)
			{
				wstring html(wHTML);
				DropListHtml *pNpcHtml = new DropListHtml();
				//m_dataHtmlSpoil.clear();

				UINT page = 0;
				UINT totalPages = static_cast<UINT>(pInfo->SpoilListFull.size() / 8);
				if((pInfo->SpoilListFull.size() % 8) != 0)
				{
					totalPages++;
				}

				html = Utils::ReplaceString(html, L"<?npctitle?>", g_NpcDb.GetClientNameByClassId(NpcId), true);
				html = Utils::ReplaceString(html, L"<?npcid?>", NpcId, true);

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
						for(UINT i=0;i<pInfo->SpoilListFull.size();i++)
						{
							ItemDropInfo& idi = pInfo->SpoilListFull[i];
							pageFlag = true;
							wstring line = templateLine;

							if( place == 0 || place == 2 || place == 4 || place == 6 || place == 8)
								line = Utils::ReplaceString(line, L"<?bgcolor?>", L"bgcolor=\"000000\"", true);
							else
								line = Utils::ReplaceString(line, L"<?bgcolor?>", L"", true);

							line = Utils::ReplaceString(line, L"<?p_npcid?>", NpcId, true);

							line = Utils::ReplaceString(line, L"<?p_itemicon?>", g_ItemDBEx.GetItemIcon(idi.itemId), true);

							wstringstream itemsa;
							itemsa << L"<font color=LEVEL>" << g_ItemDBEx.GetItemSA(idi.itemId) << L" </font>";
							line = Utils::ReplaceString(line, L"<?p_itemsa?>", itemsa.str().c_str(), true);

							line = Utils::ReplaceString(line, L"<?p_itemname?>", g_ItemDBEx.GetItemName(idi.itemId), true);


							line = Utils::ReplaceString(line, L"<?p_min_drop?>", idi.minCount, true);
							line = Utils::ReplaceString(line, L"<?p_max_drop?>", idi.maxCount, true);


							if(idi.chance > 100)
								idi.chance = 100.0;

							wstringstream porcentaje;
							porcentaje << idi.chance;

							line = Utils::ReplaceString(line, L"<?p_chance?>", porcentaje.str().c_str(), true);

							linesStream << line << endl;
							counter++;
							place++;
							if((counter%8) == 0)
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

								//m_CategoriesPages[n].m_Pages.push_back(templ);
								pNpcHtml->m_Pages.push_back(templ);
								linesStream.str(L"");
								pageFlag = false;
								page++;
								place = 0;
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
							pNpcHtml->m_Pages.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
							place = 0;
						}
					}
				}

				//here push back the html vector into main map

				m_dataHtmlSpoil.insert(pair<INT32, DropListHtml*>(NpcId, pNpcHtml));
			}
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find html - npc_spoil_info.htm !", __FUNCTION__);
		}

		//Drops
		const WCHAR* wHTML2 = g_HtmlCache.Get(L"npc_drop_info.htm");
		if(wHTML2)
		{			
			if(pInfo->DropListFull.size() > 0)
			{
				wstring html(wHTML2);
				DropListHtml *pNpcHtml = new DropListHtml();
				//m_dataHtmlSpoil.clear();

				UINT page = 0;
				UINT totalPages = static_cast<UINT>(pInfo->DropListFull.size() / 8);
				if((pInfo->DropListFull.size() % 8) != 0)
				{
					totalPages++;
				}
				
				html = Utils::ReplaceString(html, L"<?npctitle?>", g_NpcDb.GetClientNameByClassId(NpcId), true);
				html = Utils::ReplaceString(html, L"<?npcid?>", NpcId, true);

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
						for(UINT i=0;i<pInfo->DropListFull.size();i++)
						{
							ItemDropInfo& idi = pInfo->DropListFull[i];
							pageFlag = true;
							wstring line = templateLine;

							if( place == 0 || place == 2 || place == 4 || place == 6 || place == 8)
								line = Utils::ReplaceString(line, L"<?bgcolor?>", L"bgcolor=\"000000\"", true);
							else
								line = Utils::ReplaceString(line, L"<?bgcolor?>", L"", true);

							line = Utils::ReplaceString(line, L"<?p_npcid?>", NpcId, true);

							line = Utils::ReplaceString(line, L"<?p_itemicon?>", g_ItemDBEx.GetItemIcon(idi.itemId), true);

							wstringstream itemsa;
							itemsa << L"<font color=LEVEL>" << g_ItemDBEx.GetItemSA(idi.itemId) << L" </font>";
							line = Utils::ReplaceString(line, L"<?p_itemsa?>", itemsa.str().c_str(), true);





							wstringstream itemnamegrp;
							itemnamegrp << L"<font color=LEVEL>Group " << idi.groupId << L"</font>: " << g_ItemDBEx.GetItemName(idi.itemId);


							line = Utils::ReplaceString(line, L"<?p_itemname?>",itemnamegrp.str().c_str(), true);



//							if (idi.itemId == 57)
//							{
//								DOUBLE* lpAdenaRate2 = (DOUBLE*)0xBEF260;
//
//								double adenaRate = (*lpAdenaRate2);
//
//								line = Utils::ReplaceString(line, L"<?p_min_drop?>", static_cast<INT32>(static_cast<double>(idi.minCount) * adenaRate), true);
//								line = Utils::ReplaceString(line, L"<?p_max_drop?>", static_cast<INT32>(static_cast<double>(idi.maxCount) * adenaRate), true);
//							}
//							else if(idi.itemId == 6360 || idi.itemId == 6361 || idi.itemId == 6362)
//							{
//								line = Utils::ReplaceString(line, L"<?p_min_drop?>", static_cast<INT32>(static_cast<double>(idi.minCount) * m_SealStoneRate), true);
//								line = Utils::ReplaceString(line, L"<?p_max_drop?>", static_cast<INT32>(static_cast<double>(idi.maxCount) * m_SealStoneRate), true);
//							}
//							else
//							{
//								line = Utils::ReplaceString(line, L"<?p_min_drop?>", idi.minCount, true);
//								line = Utils::ReplaceString(line, L"<?p_max_drop?>", idi.maxCount, true);
//							}


								line = Utils::ReplaceString(line, L"<?p_min_drop?>", idi.minCount, true);
								line = Utils::ReplaceString(line, L"<?p_max_drop?>", idi.maxCount, true);

							if(idi.chance > 100)
								idi.chance = 100.0;

							wstringstream porcentaje;
							porcentaje << idi.chance;

							line = Utils::ReplaceString(line, L"<?p_chance?>", porcentaje.str().c_str(), true);

							linesStream << line << endl;
							counter++;
							place++;
							if((counter%8) == 0)
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

								//m_CategoriesPages[n].m_Pages.push_back(templ);
								pNpcHtml->m_Pages.push_back(templ);
								linesStream.str(L"");
								pageFlag = false;
								page++;
								place = 0;
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
							pNpcHtml->m_Pages.push_back(templ);
							linesStream.str(L"");
							pageFlag = false;
							page++;
							place = 0;
						}
					}
				}

				//here push back the html vector into main map

				m_dataHtml.insert(pair<INT32, DropListHtml*>(NpcId, pNpcHtml));
			}
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find html - npc_drop_info.htm !", __FUNCTION__);
		}
	}

	unguard;
}

void CDropList::OnDie(CNPC *pNpc, CCreature *pKiller)
{
	guard;
	if(m_enabled && pNpc->ValidCreature() && !g_RecargaEnProceso)
	{
	//	g_DropRaidsCustom.Handle(pNpc,pKiller);


		map<INT32, NpcDropInfo*>::iterator it = m_data.find(pNpc->pSD->nNpcClassID);
		if(it!=m_data.end())
		{
			NpcDropInfo* pInfo = it->second;
			if(pInfo && pNpc->pContributeData)
			{
				double levelPenalty = 1.0;

				INT32 mostContributeLevel = pNpc->pContributeData->contributorLevel;
				INT32 npcLevel = pNpc->pSD->nLevel;
				INT32 diffLevel = 0;
				if(mostContributeLevel > 0)
				{					
					diffLevel = mostContributeLevel - npcLevel;
				}else if(pKiller->ValidCreature())
				{
					diffLevel = pKiller->pSD->nLevel - npcLevel;
				}
				if(diffLevel > 0)
				{
					if(diffLevel > 9)
					{
						levelPenalty = 0.125 / (double)diffLevel;
					}else if(diffLevel == 9)
					{
						levelPenalty = 0.125;
					}else if(diffLevel > 5)
					{
						levelPenalty = 0.5;
					}
				}

			//	g_Log.Add(CLog::Blue, "[%s] levelPenalty[%f] diffLevel[%d]", __FUNCTION__, levelPenalty, diffLevel);


				DOUBLE* lpAdenaRate = (DOUBLE*)0xBEF260;
				DOUBLE* lpDropRate = (DOUBLE*)0xBEF268;

				double itemRate = (*lpDropRate);
				double adenaRate = (*lpAdenaRate);

				itemRate *= levelPenalty;
				adenaRate *= levelPenalty;

				if(g_DnNSystem.IsEnabled())
				{
					itemRate *= g_DnNSystem.GetRate(DnN::RateDrop);
					adenaRate *= g_DnNSystem.GetRate(DnN::RateAdena);
				}

				User *pUser = User::GetUserBySID(&pNpc->pContributeData->contributorId);
				if(pUser->ValidUser())
				{
					if(!pNpc->IsInRange(pUser, 2000))
					{
						pUser = 0;
					}
				}

				if(!pUser->ValidUser())
				{
					pUser = pKiller->GetUser();
					if(pKiller->IsSummon())
					{
						pUser = pKiller->CastSummon()->GetMaster();
					}
					if(pUser->ValidUser())
					{
						if(!pNpc->IsInRange(pUser, 2000))
						{
							pUser = 0;
						}
					}
				}

				double itemRateOnlyChance = 1.0;

				double itemRateBonus = 1.0;
				double adenaBonus = 1.0;
				double raidBossBonus = 1.0;
				double raidBossOnlyChanceBonus = 1.0;
				double epicBossBonus = 1.0;
				double onlyChanceBonus = 1.0;

				//Champion NPC
				if(g_ChampionNpc.IsEnabled())
				{
					int nTeam = pNpc->pSD->teamType;
					int nClassID = pNpc->pSD->nNpcClassID;
					if(nTeam)
					{
						if(g_ChampionNpc.IsChampionNPC(nClassID))
						{
							ChampionNpcInfo* pInfo = g_ChampionNpc.GetChampionData(nClassID);
							
							if(nTeam == 1)
							{
								itemRate *= pInfo->blue_drop;
								adenaRate *= pInfo->blue_adena;
							}
							else if(nTeam == 2)
							{
								itemRate *= pInfo->red_drop;
								adenaRate *= pInfo->red_adena;
							}

						}
					}
				}

				if(pUser->ValidUser())
				{
					pUser->GetDropBonuses(itemRateBonus, adenaBonus, raidBossBonus, raidBossOnlyChanceBonus, epicBossBonus, onlyChanceBonus);

					if(m_debugMsg)
					{
						g_Log.Add(CLog::Blue, "[%s] User[%S] Npc[%S][%d] itemRate[%f] adenaRate[%f] itemBonus[%f] adenaBonus[%f] rbBonus[%f] rbOnlyChanceBonus[%f], epicBonus[%f] onlyChanceBonus[%f]", __FUNCTION__,
							pUser->pSD->wszName, pNpc->pSD->wszName, pNpc->pSD->nNpcClassID, itemRate, adenaRate, itemRateBonus, adenaBonus, raidBossBonus, raidBossOnlyChanceBonus,
							epicBossBonus, onlyChanceBonus);
					}

					if(!pNpc->IsZZoldagu() && !pNpc->IsBoss())
					{
						if(pUser->pSD->vipLevel > 0)
						{
							/* VipSystem */
							itemRate *= g_VIPSystem.GetDropRate(pUser);
							adenaRate *= g_VIPSystem.GetAdenaRate(pUser);
						}

						/* Happy Hours */
						itemRate *= g_HappyHours.GetDropRate(pUser);
						adenaRate *= g_HappyHours.GetAdenaRate(pUser);

						/* Skill Effects */
						itemRate *= itemRateBonus;
						itemRateOnlyChance *= onlyChanceBonus;
						adenaRate *= adenaBonus;
						m_SealStoneRate *= adenaBonus;
					}else
					{
						INT32 npcClassId = pNpc->pSD->nNpcClassID;
						itemRate = 1.0;
						itemRate *= levelPenalty;
						//itemRateOnlyChance *= m_raidBossItemRate;
						//raid boss rates
						if(npcClassId == 1029001 || npcClassId == 1029006 || npcClassId == 1029014 || npcClassId == 1029019 || npcClassId == 1029020 || npcClassId == 1029022 || npcClassId == 1029028 || npcClassId == 1029047 || npcClassId == 1029066 || npcClassId == 1029067 || npcClassId == 1029068)
						{
							itemRateOnlyChance *= epicBossBonus;
							//epic rb
						}else
						{
							//normal rb
							itemRateOnlyChance *= raidBossOnlyChanceBonus;
							itemRate *= raidBossBonus;
						}
					}
				}
				map<int, int> droppedItems;
				map<int, int>::iterator droppedIter;

				//Item Make List
				if(pInfo->itemMakeList.size() > 0)
				{
					for(int n=0;n<pInfo->itemMakeList.size();n++)
					{
						ItemDropInfo& idi = pInfo->itemMakeList[n];
						double itemChance = idi.chance * itemRate;
						if(itemChance < 100.0)
						{
							itemChance *= itemRateOnlyChance;
							if(itemChance > 100.0)
							{
								itemChance = 100.0;
							}
						}
						INT32 minCount = idi.minCount;
						INT32 maxCount = idi.maxCount;


						for(;itemChance > 0.0; itemChance -= 100.0)
						{
							double dice = g_Random.RandDouble(100.0);
							if(dice < itemChance)
							{
								INT32 max = maxCount - minCount + 1;
								INT32 amount = minCount;
								if(max > 1)
								{
									amount += g_Random.RandInt(max);
								}

								if(pUser->ValidUser())
								{
									double fCount = static_cast<INT32>(amount);
									fCount *= pUser->pED->itemBonus.Get(idi.itemId);
									amount = static_cast<INT32>(fCount);
								}

								if(!pNpc->pSD->nSeederSID || idi.itemId == 57 || idi.itemId == 6360 || idi.itemId == 6361 || idi.itemId == 6362)
								{
									if(amount > 0)
									{
										droppedIter = droppedItems.find(idi.itemId);
										if(droppedIter != droppedItems.end())
										{
											droppedIter->second = amount;
										}else
										{
											droppedItems.insert(pair<int, int>(idi.itemId, amount));
										}
									}
								}

								//m_SealStoneRate
							}
						}
					}
				}
				//Additional Make List
				if(pInfo->additionalMakeList.size() > 0)
				{
					for(int n=0;n<pInfo->additionalMakeList.size();n++)
					{
						ItemDropInfo& idi = pInfo->additionalMakeList[n];
						double itemChance = idi.chance * itemRate;
						INT32 minCount = idi.minCount;
						INT32 maxCount = idi.maxCount;

						if(itemChance < 100.0)
						{
							itemChance *= itemRateOnlyChance;
							if(itemChance > 100.0)
							{
								itemChance = 100.0;
							}
						}

						if(idi.itemId == 57 /*|| idi.itemId == 6360 || idi.itemId == 6361 || idi.itemId == 6362*/)
						{
							itemChance = idi.chance * levelPenalty;
							double mc = static_cast<double>(minCount) * adenaRate;
							minCount = static_cast<int>(mc);
							mc = static_cast<double>(maxCount) * adenaRate;
							maxCount = static_cast<int>(mc);
						}

						if(/*idi.itemId == 57 ||*/ idi.itemId == 6360 || idi.itemId == 6361 || idi.itemId == 6362)
						{
							itemChance = idi.chance * levelPenalty;
							double mc = static_cast<double>(minCount) * m_SealStoneRate;
							minCount = static_cast<int>(mc);
							mc = static_cast<double>(maxCount) * m_SealStoneRate;
							maxCount = static_cast<int>(mc);
						}

						//m_SealStoneRate
						for(;itemChance > 0.0; itemChance -= 100.0)
						{
							double dice = g_Random.RandDouble(100.0);
							if(dice < itemChance)
							{
								INT32 max = maxCount - minCount + 1;
								INT32 amount = minCount;
								if(max > 1)
								{
									amount += g_Random.RandInt(max);
								}
								if(pUser->ValidUser())
								{
									double fCount = static_cast<INT32>(amount);
									fCount *= pUser->pED->itemBonus.Get(idi.itemId);
									amount = static_cast<INT32>(fCount);
								}
								if(!pNpc->pSD->nSeederSID || idi.itemId == 57 || idi.itemId == 6360 || idi.itemId == 6361 || idi.itemId == 6362)
								{
									if(amount > 0)
									{
										droppedIter = droppedItems.find(idi.itemId);
										if(droppedIter != droppedItems.end())
										{
											droppedIter->second += amount;
										}else
										{
											droppedItems.insert(pair<int, int>(idi.itemId, amount));
										}
									}
								}
							}
						}
					}
				}
				//Additional Make Multi List
				if(pInfo->additionalMakeMultiList.size() > 0)
				{
					for(int groupIndex = 0;groupIndex < pInfo->additionalMakeMultiList.size(); groupIndex++)
					{
						GroupDropInfo& gdi = pInfo->additionalMakeMultiList[groupIndex];
						if(gdi.items.size() > 0)
						{
							double groupChance = gdi.chance * itemRate;


							if(pNpc->IsZZoldagu() && pNpc->IsBoss())
							{
								groupChance = gdi.chance * m_raidBossItemRate;
							}

							if(gdi.adenaGroup)
							{
								if(diffLevel < 10)
								{
									groupChance = gdi.chance;
								}
							}else if(groupChance < 100.0)
							{
								groupChance *= itemRateOnlyChance;
								if(groupChance > 100.0)
								{
									groupChance = 100.0;
								}
							}
							if(m_debugMsg)
							{
								g_Log.Add(CLog::Blue, "[%s] group[%d] rate[%f]", __FUNCTION__, groupIndex, groupChance);
							}
							for(;groupChance > 0; groupChance -= 100.0)
							{
								double dice = g_Random.RandDouble(100.0);
						//		g_Log.Add(CLog::Blue, "[%s] group[%d] rate[%f] dice[%f]", __FUNCTION__, groupIndex, groupChance, dice);
								if(dice < groupChance)
								{
									double itemDice = 0.0;
									if(gdi.itemsChanceSum > 100.0)
									{
										itemDice = g_Random.RandDouble(gdi.itemsChanceSum);
									}else
									{
										itemDice = g_Random.RandDouble(100.0);
									}

									double itemChance = 0.0;

									//drop one of items
									for(int itemIndex = 0; itemIndex < gdi.items.size(); itemIndex++)
									{
										ItemDropInfo& idi = gdi.items[itemIndex];
										itemChance += idi.chance;
										if(m_debugMsg)
										{
											g_Log.Add(CLog::Blue, "[%s] group[%d] rate[%f] dice[%f] itemChance[%f] itemDice[%f] ItemName[%S]", __FUNCTION__, groupIndex+1, groupChance, dice, itemChance, itemDice, g_ItemDBEx.GetItemName(idi.itemId).c_str());
										}
										if(itemDice < itemChance)
										{
											INT32 minCount = idi.minCount;
											INT32 maxCount = idi.maxCount;
											INT32 max = maxCount - minCount + 1;
											INT32 amount = minCount;
											if(max > 1)
											{
												amount += g_Random.RandInt(max);
											}
											if(pUser->ValidUser())
											{
												double fCount = static_cast<INT32>(amount);
												fCount *= pUser->pED->itemBonus.Get(idi.itemId);
												amount = static_cast<INT32>(fCount);


												if(pUser->pSD->vipLevel > 0 && idi.itemId == 57 || idi.itemId == 6360 || idi.itemId == 6361 || idi.itemId == 6362)
												{
													amount *= g_VIPSystem.GetAdenaRate(pUser);
												}
											}

											if(m_debugMsg)
											{
												g_Log.Add(CLog::Blue, "Min[%d] Max[%d] ItemId[%d][%d][%d] Count[%d] isSown[%d][%d][%d]", minCount, maxCount, idi.itemId, idi.minCount, idi.maxCount, amount, pNpc->pSD->isSown, pNpc->pSD->nSeedType, pNpc->pSD->nSeederSID);
											}
											if(!pNpc->pSD->nSeederSID || idi.itemId == 57 || idi.itemId == 6360 || idi.itemId == 6361 || idi.itemId == 6362)
											{
												if(amount > 0)
												{
													droppedIter = droppedItems.find(idi.itemId);
													if(droppedIter != droppedItems.end())
													{
														droppedIter->second = amount;
													}else
													{
														droppedItems.insert(pair<int, int>(idi.itemId, amount));
													}
												}
											}
											break;
										}
									}
									//termina el for(int itemIndex = 0; itemIndex < gdi.items.size(); itemIndex++)


								}
							}
						}
					}
				}


				for(droppedIter = droppedItems.begin();droppedIter != droppedItems.end();droppedIter++)
				{
					int ItemId = droppedIter->first;
					int Amount = droppedIter->second;

					bool dropitem = true;

					if(pUser->ValidUser() && !g_RecargaEnProceso)
					{
						if (!pUser->pED->dropItems)
						{
							for(UINT n=0;n<blockedDropItems.size();n++)
							{
								if(blockedDropItems[n] == ItemId)
								{	
									dropitem=false;
									break;
								}
							}
						}
					}

					if (g_CambiarIDSealStones)
					{
						if (ItemId ==6361)
						{
							Amount *=5;
							ItemId = 5575;
						}
						else if(ItemId ==6362)
						{
							Amount *=10;
							ItemId = 5575;
						}
						else if(ItemId ==6360)
						{
							Amount *=3;
							ItemId = 5575;
						}
					}

					if(dropitem)
					{
						if( droppedIter->second >=0 )
						{
							if(g_AutoLoot.IsEnabled())
							{
								if(!g_AutoLoot.Handle(pNpc, pKiller, ItemId, Amount))
								{
									pNpc->AddItemToInventory(ItemId, Amount);
									//Sleep(customDrop_delay);
								}
							}else
							{
								pNpc->AddItemToInventory(ItemId, Amount);
								//Sleep(customDrop_delay);
							}
						}else
						{
							g_Log.Add(CLog::Error, "[%s] Invalid amount - item[%d] amount[%d] npc[%S] user[%S]", __FUNCTION__, ItemId, Amount, pNpc->pSD->wszName, pKiller->pSD->wszName);
						}
					}
				}
			}
		}

		g_DropRaidsCustom.Handle(pNpc, pKiller);
		g_Achivments.SetUser_KillMob(pNpc, pKiller);
	}
	unguard;
}

void CDropList::ItemsNotDroppedLoad()
{	
	guard;
	wstring filew = ReadFileW(g_ChangeFolders.ItemsNotDropped_txt);
	if(filew.size() > 0)
	{
		wstringstream file(filew);
		wstring line;
		while(getline(file, line))
		{
			if(line.size() > 4)
			{
				if( line[0] == L'/' || line[0] == L';' )
					continue;

				if( line.find(L"item_begin") == 0 )
				{
					//item_begin	item_id=20424	item_end					
					int itemId = Parser::ParseOptionInt(line, L"item_id");

					if(itemId > 0)
					{
						itemsnotdropped.push_back(itemId);
					}
				}
			}
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find ..//Script//ItemsNotDropped.txt !", __FUNCTION__);
	}
	unguard;
}

bool CDropList::ItemForNotDrop(int itemid)
{
	for(list<int>::iterator Iter = itemsnotdropped.begin();Iter!=itemsnotdropped.end();Iter++)
	{
		if((*Iter) == itemid)
		{
			return true;
		}
	}

	return false;
}
