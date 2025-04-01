#include "StdAfx.h"
#include "DropRaidsCustom.h"
#include "ObjectDB.h"
#include "AutoLoot.h"

DropRaidsCustom g_DropRaidsCustom;

extern BOOL g_RecargaEnProceso;


bool customDrop_Enabled = FALSE;
INT32 customDrop_delay = 0;

void DropRaidsCustom::LoadINI()
{
	customDrop_Enabled = false;

	m_CustomDrop.clear();
	const TCHAR* sectionName = _T("DROP_CUSTOM");

	customDrop_delay = GetPrivateProfileInt(sectionName, _T("Delay"), 0, g_CustomConfigFile);

	//all;lev_min;lev_max{{item_name;min;max;chance};{item_name;min;max;chance}}
	//boss_name;lev_min;lev_max{{item_name;min;max;chance};{item_name;min;max;chance}}

	if(GetPrivateProfileInt(sectionName, _T("Enabled"), 0, g_CustomConfigFile))
	{
		for(UINT n=1;n<=100;n++)
		{
			TCHAR sString[8192];
			tstringstream skey;
			skey << n << "_Drop";
			if(GetPrivateProfileString(sectionName,skey.str().c_str(), 0, sString, 8190, g_CustomConfigFile))
			{
				CustomDropInfo map_customDrop;
		
				tstringstream sstr; sstr << sString;
				tstring sValue;
				while(sstr >> sValue)
				{
				//----------------------------------------
					int npcId = 0;
					int level_min = 0;
					int level_max = 0;
					int contador1 = 0;

					tstring linea = sValue.c_str();

					std::wstring subs;
					std::wstringstream wss1(linea);
					while(std::getline(wss1, subs, L';'))
					{
				//		g_Log.Add(CLog::Error, "PARAM[%S]",subs.c_str());
						if (contador1 == 0)
						{
							int tmp_npcid = 0;
							if (subs == L"ALLBOSS")
								tmp_npcid = ALLBOSS;
							else if (subs == L"ALLMOBS")
								tmp_npcid = ALLMOBS;
							else
								tmp_npcid = g_ObjectDB.GetClassIdFromName(subs.c_str());

							map_customDrop.npcId = tmp_npcid;
						}
						else if (contador1 == 1)
							map_customDrop.level_min = _wtoi(subs.c_str());
						else if (contador1 == 2)
						{
							map_customDrop.level_max =  _wtoi(subs.c_str());
							break;
						}
						contador1++;
					}
			//		g_Log.Add(CLog::Error, "npcId[%d], level_min[%d], level_max[%d]",npcId, level_min, level_max);

					tstring sdrop =L"";
					sdrop = Utils::ReplaceStringW(linea, L"{{", L"{", true);
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
						CustomItemDropInfo info;
						wstring drop = Utils::ReplaceStringW(subs2, L";", L" ", true);
						tstringstream sstr2; sstr2 << drop;
						tstring drop2;
						while(sstr2 >> drop2)
						{
						//	g_Log.Add(CLog::Error, "PARAM[%S]",drop2.c_str());

							if (contador3 == 0)
								info.itemId = g_ObjectDB.GetClassIdFromName(drop2.c_str());
							else if (contador3 == 1)
								info.minCount = _wtoi(drop2.c_str());
							else if (contador3 == 2)
								info.maxCount = _wtoi(drop2.c_str());
							else if (contador3 == 3)
								info.chance = _wtof(drop2.c_str());;

							contador3++;
						}
						map_customDrop.DropList.push_back(info);
						
					}

				//	g_Log.Add(CLog::Error, "----------------------------------------");

				//----------------------------------------
				}
				m_CustomDrop.push_back(map_customDrop);
			}
		}
	}


//			for(UINT n=0;n<m_CustomDrop.size();n++)	//LISTA DE CONFIGS
//			{
//				g_Log.Add(CLog::Error, "npcId[%d] level_min[%d] level_max[%d]", m_CustomDrop[n].npcId, m_CustomDrop[n].level_min, m_CustomDrop[n].level_max);

//				for(UINT i=0;i<m_CustomDrop[n].DropList.size();i++)
//				{
//					INT32 ItemId = m_CustomDrop[n].DropList[i].itemId;
//					INT32 minCount = m_CustomDrop[n].DropList[i].minCount;
//					INT32 maxCount = m_CustomDrop[n].DropList[i].maxCount;
//					double chance = m_CustomDrop[n].DropList[i].chance;
//
//					g_Log.Add(CLog::Error, "ItemId[%d] minCount[%d] maxCount[%d] chance[%f]",ItemId,minCount,maxCount,chance);
//				}
//			
//				g_Log.Add(CLog::Error, "----------------------------------------");
//			}

		customDrop_Enabled = GetPrivateProfileInt(sectionName, _T("Enabled"), 0, g_CustomConfigFile);
}

void DropRaidsCustom::Handle(CNPC* pNpc, CCreature* pKiller)
{
	guard;
	if(customDrop_Enabled)
	{
		if(pNpc->pContributeData)
		{
			double levelPenalty = 1.0;

			INT32 mostContributeLevel = pNpc->pContributeData->contributorLevel;
			INT32 npcLevel = pNpc->pSD->nLevel;
			INT32 npcClassId = pNpc->pSD->nNpcClassID;
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

			//----------------------------------


//			map<int, int> droppedItems;
//			map<int, int>::iterator droppedIter;
			
			vector<CustomDroppedItems> m_droppedItems;

			for(UINT n=0;n<m_CustomDrop.size();n++)
			{
				if(pNpc->IsBoss())
				{
					if(m_CustomDrop[n].npcId == npcClassId)
					{
						for(UINT i=0;i<m_CustomDrop[n].DropList.size();i++)
						{
							INT32 ItemId = m_CustomDrop[n].DropList[i].itemId;
							INT32 minCount = m_CustomDrop[n].DropList[i].minCount;
							INT32 maxCount = m_CustomDrop[n].DropList[i].maxCount;
							double chance = m_CustomDrop[n].DropList[i].chance;

							if (g_Random.RandDouble(100.0) < chance * levelPenalty)
							{
								int TotalCount = g_Random.RandIntMinMax(minCount,maxCount);

								CustomDroppedItems DropTmp;
								DropTmp.itemId = ItemId;
								DropTmp.Count = TotalCount;
								m_droppedItems.push_back(DropTmp);

//								map<int, int>::iterator droppedIter;
//								droppedIter = droppedItems.find(ItemId);
//								if(droppedIter != droppedItems.end())
//								{
//									droppedIter->second += TotalCount;
//								}else
//								{
//									droppedItems.insert(pair<int, int>(ItemId, TotalCount));
//								}
							}
						}
					}
					else if(m_CustomDrop[n].npcId == ALLBOSS)
					{
						bool existe = false;
						for(UINT h=0;h<m_CustomDrop.size();h++)
						{
							if(m_CustomDrop[h].npcId == npcClassId)
								existe = true;
						}
						if(!existe)
						{
							if(npcLevel >= m_CustomDrop[n].level_min && npcLevel <= m_CustomDrop[n].level_max)
							{
								for(UINT i=0;i<m_CustomDrop[n].DropList.size();i++)
								{
									INT32 ItemId = m_CustomDrop[n].DropList[i].itemId;
									INT32 minCount = m_CustomDrop[n].DropList[i].minCount;
									INT32 maxCount = m_CustomDrop[n].DropList[i].maxCount;
									double chance = m_CustomDrop[n].DropList[i].chance;

									if (g_Random.RandDouble(100.0) < chance * levelPenalty)
									{
										int TotalCount = g_Random.RandIntMinMax(minCount,maxCount);

										CustomDroppedItems DropTmp;
										DropTmp.itemId = ItemId;
										DropTmp.Count = TotalCount;
										m_droppedItems.push_back(DropTmp);

//										map<int, int>::iterator droppedIter;
//										droppedIter = droppedItems.find(ItemId);
//										if(droppedIter != droppedItems.end())
//										{
//											droppedIter->second += TotalCount;
//										}else
//										{
//											droppedItems.insert(pair<int, int>(ItemId, TotalCount));
//										}
									}
								}
							}
						}
					}
				}
				else if(!pNpc->IsZZoldagu() && !pNpc->IsBoss() && !pNpc->IsSummon() && !pNpc->IsPet() && pNpc->pSD->nClass==1)
				{
					if (m_CustomDrop[n].npcId == npcClassId)
					{
						for(UINT i=0;i<m_CustomDrop[n].DropList.size();i++)
						{
							INT32 ItemId = m_CustomDrop[n].DropList[i].itemId;
							INT32 minCount = m_CustomDrop[n].DropList[i].minCount;
							INT32 maxCount = m_CustomDrop[n].DropList[i].maxCount;
							double chance = m_CustomDrop[n].DropList[i].chance;

							if (g_Random.RandDouble(100.0) < chance * levelPenalty)
							{
								int TotalCount = g_Random.RandIntMinMax(minCount,maxCount);

								CustomDroppedItems DropTmp;
								DropTmp.itemId = ItemId;
								DropTmp.Count = TotalCount;
								m_droppedItems.push_back(DropTmp);

//								map<int, int>::iterator droppedIter;
//								droppedIter = droppedItems.find(ItemId);
//								if(droppedIter != droppedItems.end())
//								{
//									droppedIter->second += TotalCount;
//								}else
//								{
//									droppedItems.insert(pair<int, int>(ItemId, TotalCount));
//								}
							}
						}
					}
					else if(m_CustomDrop[n].npcId == ALLMOBS)
					{
						bool existe = false;
						for(UINT h=0;h<m_CustomDrop.size();h++)
						{
							if(m_CustomDrop[h].npcId == npcClassId)
								existe = true;
						}
						if(!existe)
						{
							if(npcLevel >= m_CustomDrop[n].level_min && npcLevel <= m_CustomDrop[n].level_max)
							{
								for(UINT i=0;i<m_CustomDrop[n].DropList.size();i++)
								{
									INT32 ItemId = m_CustomDrop[n].DropList[i].itemId;
									INT32 minCount = m_CustomDrop[n].DropList[i].minCount;
									INT32 maxCount = m_CustomDrop[n].DropList[i].maxCount;
									double chance = m_CustomDrop[n].DropList[i].chance;

									if (g_Random.RandDouble(100.0) < chance * levelPenalty)
									{
										int TotalCount = g_Random.RandIntMinMax(minCount,maxCount);

										CustomDroppedItems DropTmp;
										DropTmp.itemId = ItemId;
										DropTmp.Count = TotalCount;
										m_droppedItems.push_back(DropTmp);

//										map<int, int>::iterator droppedIter;
//										droppedIter = droppedItems.find(ItemId);
//										if(droppedIter != droppedItems.end())
//										{
//											droppedIter->second += TotalCount;
//										}else
//										{
//											droppedItems.insert(pair<int, int>(ItemId, TotalCount));
//										}
									}
								}
							}
						}
					}
				}
			}

			for(UINT h=0;h<m_droppedItems.size();h++)
			{
				if( m_droppedItems[h].Count >=0 )
				{
					if(g_AutoLoot.IsEnabled())
					{
						if(!g_AutoLoot.Handle(pNpc, pKiller, m_droppedItems[h].itemId, m_droppedItems[h].Count))
						{

				//				AtomicDropItem2 asd;

								  //asd.base = (*(PINT64)0x980038);
				//				  asd.mNpcSID = pNpc->pSD->nObjectID;
				//				  asd.mItemClassId = m_droppedItems[h].itemId;
				//				  asd.mItemCount = m_droppedItems[h].Count;
				//				  asd.mvPos.z = pNpc->pSD->Pos.z;
				//				  asd.mvPos.y = pNpc->pSD->Pos.y;
				//				  asd.mvPos.x = pNpc->pSD->Pos.x;
				//				  asd.mContributorID = pNpc->pContributeData->contributorId;
				

				//				  g_Log.Add(CLog::Error, "contributePower[%d] contributorId[%d] mNpcSID[%d]",pNpc->pContributeData->contributePower,pNpc->pContributeData->contributorId,pNpc->pSD->nObjectID);

				//				typedef void(*r)(AtomicDropItem2*);
				//				r(0x004351F0L)(&asd);

							/*
							User *pUser = User::GetUserBySID(&pNpc->pContributeData->contributorId);
							if(pUser->ValidUser())
							{
								if(CItem *pItem = g_ObjectDB.CreateItem(m_droppedItems[h].itemId))
								{
									CContributeDataForEvent* tmp2;
									typedef CContributeDataForEvent*(*x)(__int64);
									tmp2 = x(0x429290L)(168);			

									CContributeDataForEvent* tmp3;
									typedef CContributeDataForEvent*(*f)(CContributeDataForEvent*, User*);
									tmp3 = f(0x6F9BF0L)(tmp2, pUser);		//CContributeDataForEvent::CContributeDataForEvent

									//void __stdcall CItem__WriteLock(CItem *this, const wchar_t *a2, __int64 a3)
									//CItem::WriteLock(v20, L".\\AtomicJob.cpp", 1283i64);
									typedef void(*q)(CItem*, const wchar_t *, __int64);
									q(0x429730L)(pItem, L".\\AtomicJob.cpp", 1283);

									//CIOObject::AddTimer(v23, 20000u, 0);
									typedef void(*w)(CContributeDataForEvent*, UINT, INT32);
									w(0x6261D0L)(tmp3, 20000, 0);

									pItem->pSID->nItemState = 1;
									pItem->pSID->nItemAmount = m_droppedItems[h].Count;
									pItem->nUnkn5 = pUser->nObjectID;

									//CIOObject::AddTimer(v20, 5000u, 0);
									typedef void(*s)(CItem*, UINT, INT32);
									s(0x6261D0L)(pItem, 5000, 0);

									//void __stdcall CItem::WriteUnLock(CItem *this)
									typedef void(*y)(CItem*);
									y(0x4319D0L)(pItem);


									FVector tmp;
									typedef FVector(*r)(FVector*, FVector*);
									tmp = r(0x00429590L)(&pNpc->pSD->Pos, &pNpc->pSD->Pos);

									g_World.PutItem(pItem, tmp);




								}
							}*/

							pNpc->AddItemToInventory(m_droppedItems[h].itemId, m_droppedItems[h].Count);
							//Sleep(customDrop_delay);
						}
					}else
					{
						pNpc->AddItemToInventory(m_droppedItems[h].itemId, m_droppedItems[h].Count);
					}
				}else
				{
					g_Log.Add(CLog::Error, "[%s] Invalid amount - item[%d] amount[%d] npc[%S] user[%S]", __FUNCTION__, m_droppedItems[h].itemId, m_droppedItems[h].Count, pNpc->pSD->wszName, pKiller->pSD->wszName);
				}
			}

//			for(droppedIter = droppedItems.begin();droppedIter != droppedItems.end();droppedIter++)
//			{
//				if( droppedIter->second >=0 )
//				{
//					if(g_AutoLoot.IsEnabled())
//					{
//						if(!g_AutoLoot.Handle(pNpc, pKiller, droppedIter->first, droppedIter->second))
//						{
//							pNpc->AddItemToInventory(droppedIter->first, droppedIter->second);
//						}
//					}else
//					{
//						pNpc->AddItemToInventory(droppedIter->first, droppedIter->second);
//					}
//				}else
//				{
//					g_Log.Add(CLog::Error, "[%s] Invalid amount - item[%d] amount[%d] npc[%S] user[%S]", __FUNCTION__, droppedIter->first, droppedIter->second, pNpc->pSD->wszName, pKiller->pSD->wszName);
//				}
//			}
		}
	}
	unguard;
}
