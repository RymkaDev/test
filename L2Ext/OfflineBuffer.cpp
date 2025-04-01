#include "StdAfx.h"
#include "SocketDB.h"
#include "OfflineBuffer.h"
#include "OfflineShop.h"
#include "OfflineSocketDB.h"
#include "SkillAcquireDB.h"
#include "HtmlCache.h"
#include "ClassManager.h"
#include "TerritoryData.h"
#include "OfflineShopRestore.h"
#include "DB.h"

COfflineBuffer g_OfflineBuffer;

COfflineBuffer::COfflineBuffer()
{
}

COfflineBuffer::~COfflineBuffer()
{
}

list<int> BufferClasses;
list<int> Buffs;

/*
[OfflineBuffer]
Enabled=1
;Offline Store Title Color
TitleColor=255
;Offline Buff Store in Seconds
OfflineBuffTime=3600
;Class Id's which players can sell buffs - separate with space
BufferClasses=15 16 17 21 28 29 30 41 42 43 50 51 52 97 98 100 104 105 107 112 115 116
;Buff Skill ID which can be used for sell
BuffID=1218 1204 1040 1068 1035 1189 1045 1048 1036 1191 1182 1059 1303 1259 1392 1393 1352 1353 1354 1355 1356 1357 1363 1078 1062 1077 1085 1087 1240 1242 1243 1268 1388 1389 1304 1307 1323 271 272 273 274 275 276 277 307 309 310 311 365 264 265 266 267 268 269 270 304 305 349 363 364 306 308 366 1311 1413 1086 1391 1390 1310 1306 1218 4700 4699 4702 4703
;Min Price For Sell
MinPrice=100
;Max Price For Sell
MaxPrice=500000
;Required item id
RequiredItemId=9450
RequiredItemCount=1
;Tells if system will delete required item when offline buff shop got activated
ConsumeRequiredItem=0
;Allow Offline Buff Stores in specific zones (into territorydata.txt -> BUFF_ZONE)
AllowOnlyInSpecificZone=0
*/

void COfflineBuffer::Initialize()
{
	const TCHAR* section = _T("OfflineBuffer");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), FALSE, g_ConfigFile);
	nTitleColor = GetPrivateProfileInt(section, _T("TitleColor"), FALSE, g_ConfigFile);
	nTimeForShop = GetPrivateProfileInt(section, _T("OfflineBuffTime"), FALSE, g_ConfigFile);
	nMinPrice = GetPrivateProfileInt(section, _T("MinPrice"), FALSE, g_ConfigFile);
	nMaxPrice = GetPrivateProfileInt(section, _T("MaxPrice"), FALSE, g_ConfigFile);
	m_RequiredItemId = GetPrivateProfileInt(section, _T("RequiredItemId"), 0, g_ConfigFile);
	m_RequiredItemCount = GetPrivateProfileInt(section, _T("RequiredItemCount"), 0, g_ConfigFile);
	m_ConsumeRequiredItem = GetPrivateProfileInt(section, _T("ConsumeRequiredItem"), 0, g_ConfigFile);
	m_allowOnlySpecificZone = GetPrivateProfileInt(section, _T("AllowOnlyInSpecificZone"), FALSE, g_ConfigFile);
	m_MinDistance = GetPrivateProfileDouble(section, _T("MinBuffStoreDistance"), 0, g_ConfigFile);

	BufferClasses.clear();
	Buffs.clear();
	TCHAR tmp[8192];
	memset(tmp, 0, 8192);
	if(GetPrivateProfileString(section, _T("BufferClasses"), 0, tmp, sizeof(tmp), g_ConfigFile) > 0)
	{
		tstringstream sstr(tmp);
		int class_id = 0;
		while(sstr >> class_id)
		{
			BufferClasses.push_back(class_id);
		}
	}

	if(GetPrivateProfileString(section, _T("BuffID"), 0, tmp, sizeof(tmp), g_ConfigFile) > 0)
	{
		tstringstream sstr(tmp);
		int buff_id = 0;
		while(sstr >> buff_id)
		{
			Buffs.push_back(buff_id);
		}
	}
}

void COfflineBuffer::RequestActivateOfflineBuffShop(User *pUser)
{
	if(pUser->ValidUser())
	{
		//just show the html
		const WCHAR* wHTML = g_HtmlCache.Get(L"offline_buffer_request.htm");
		if(wHTML)
		{
			wstring html(wHTML);
			pUser->ShowHTML(L"offline_buffer_request.htm", html.c_str(), 0);
		}
	}
}

void COfflineBuffer::EnableBuffer(User *pUser, wstring wTitle, int buffprice, bool normal_char)
{
	if(pUser->ValidUser())
	{
		if( pUser->pSD->nStoreMode == 0)
		{
			//check class
			if (CheckClass(pUser->pSD->nSubJobClass[0]) || CheckClass(pUser->pSD->nSubJobClass[1]) || CheckClass(pUser->pSD->nSubJobClass[2]) || CheckClass(pUser->pSD->nSubJobClass[3]) )
			{
				if( (buffprice > nMinPrice) && (buffprice < nMaxPrice) ) //price check
				{
					if((wTitle.length()) > 0 && (wTitle.length() <= 16) ) //title check
					{
						double minDistance = GetMinDistance();
						bool rangeblock = false;

						if(minDistance > 0.0)
						{
							if(g_UserDB.AnyBuffStoreInRange(pUser->pSD->Pos, minDistance))
							{
								rangeblock = true;
							}
						}

						if(!rangeblock)
						{
							//Check which skills hass
							pUser->acquiredSkillLock.Lock(__FILEW__, __LINE__);
							for(map<int, int>::iterator Iter = pUser->mAcquiredSkill.begin();Iter!=pUser->mAcquiredSkill.end();Iter++)
							{
								if(CheckBuff(Iter->first))
								{
									//mSkills_Player_has.insert(pair<int, int>(Iter->first, Iter->second));
									pUser->pED->m_offlinesellbuffs.insert(pair<int, int>(Iter->first, Iter->second));
								}
							}
							pUser->acquiredSkillLock.Unlock();

							if(pUser->pED->m_offlinesellbuffs.size() > 0)
							{
								if(m_RequiredItemId > 0 && m_RequiredItemCount > 0)
								{
									if(!pUser->inventory.HaveItemByClassID(m_RequiredItemId, m_RequiredItemCount))
									{
										pUser->pSocket->SendSystemMessage(L"You don't have enough required item(s) to start Offline Shop.");
										return;
									}else if(m_ConsumeRequiredItem)
									{
										pUser->DeleteItemInInventory(m_RequiredItemId, m_RequiredItemCount);
									}
								}

								if( m_allowOnlySpecificZone && !pUser->pED->nInCustomBuffZone && !pUser->GetSocket()->pED->is_osr_buff)
								{
									pUser->SendSystemMessage(L"OfflineBuffer System: You cannot have an private buff store here!");
									return;
								}

								if(pUser->pSD->nStoreMode)
								{
									pUser->SendSystemMessageRed(L"OfflineBuffer System: You cannot have an private buff store at the momment!");
									return;
								}

								CParty *pParty = pUser->GetParty();
								if(pParty)
								{
									pParty->LeaveParty(pUser);
								}
								pUser->olympiadUser.OnLeaveWorld();

								//Sit Player
								pUser->SitStand();

								//Set Title and Color Title & price
								pUser->pED->nofflinesellbuffprice = buffprice;
								pUser->pED->offlineselltitle = wTitle;

								//Create Pages
								CreatePages(pUser, false);
								CreatePages(pUser, true);

								//userinfo/charinfo send -- mby not nessecary?
								pUser->SetUserInfoChanged();
								pUser->SetCharInfoChanged();

								//Set Offline & Logout
								g_OfflineShop.RequestActivateOfflineShop(pUser,true);
								pUser->GetSocket()->Send("c", LOGOUT_OK);

								g_Log.Add(CLog::Blue, "[%s] User[%S] Offline Buff Store Started! With [%d] Skills and pages[%d]!", __FUNCTION__, pUser->pSD->wszName, pUser->pED->m_offlinesellbuffs.size(), pUser->pED->m_BuffPagePlayer.size());
							}
							else
							{
								pUser->SendSystemMessage(L"OfflineBuffer System: You have no buffs to sell!");
								if(pUser->GetSocket()->pED->is_osr_buff)
									g_DB.Send("chdSd", 0xF9, CI_REQUEST_SAVE_OFFLINEBUFFSHOP, pUser->pSD->nDBID, L"", 0);
							}
						}
						else
						{
							pUser->SendSystemMessage(L"OfflineBuffer System: You cannot setup an offline buff store so close to other player!");
							if(pUser->GetSocket()->pED->is_osr_buff)
								g_DB.Send("chdSd", 0xF9, CI_REQUEST_SAVE_OFFLINEBUFFSHOP, pUser->pSD->nDBID, L"", 0);
						}
					}
					else
					{
						pUser->SendSystemMessage(L"OfflineBuffer System: The title is not correct!");
						if(pUser->GetSocket()->pED->is_osr_buff)
							g_DB.Send("chdSd", 0xF9, CI_REQUEST_SAVE_OFFLINEBUFFSHOP, pUser->pSD->nDBID, L"", 0);
					}
				}
				else
				{
					pUser->SendSystemMessage(L"OfflineBuffer System: The price which you set is not correct!");
					if(pUser->GetSocket()->pED->is_osr_buff)
						g_DB.Send("chdSd", 0xF9, CI_REQUEST_SAVE_OFFLINEBUFFSHOP, pUser->pSD->nDBID, L"", 0);
				}
			}
			else
			{
				pUser->SendSystemMessage(L"OfflineBuffer System: You class cannot be setted as offline selling mode!");
				if(pUser->GetSocket()->pED->is_osr_buff)
					g_DB.Send("chdSd", 0xF9, CI_REQUEST_SAVE_OFFLINEBUFFSHOP, pUser->pSD->nDBID, L"", 0);
			}
		}
		else
		{
			pUser->SendSystemMessage(L"OfflineBuffer System: You cannot have private buff store at the momment!");
			if(pUser->GetSocket()->pED->is_osr_buff)
				g_DB.Send("chdSd", 0xF9, CI_REQUEST_SAVE_OFFLINEBUFFSHOP, pUser->pSD->nDBID, L"", 0);
		}
	}
}

bool COfflineBuffer::CheckClass(int classid)
{
	bool ret = false;
	for(list<int>::iterator Iter = BufferClasses.begin();Iter!=BufferClasses.end();Iter++)
	{
		if((*Iter) == classid)
		{
			ret = true;
		}
	}

	return ret;
}

bool COfflineBuffer::CheckBuff(int nSkillID)
{
	bool ret = false;
	for(list<int>::iterator Iter = Buffs.begin();Iter!=Buffs.end();Iter++)
	{
		if((*Iter) == nSkillID)
		{
			ret = true;
		}
	}

	return ret;
}

bool COfflineBuffer::CheckBuffExist(User *pUser, int nSkillID)
{
	bool ret = false;
	if(pUser->ValidUser())
	{
		for(map<INT32, INT32>::iterator Iter = pUser->pED->m_offlinesellbuffs.begin(); Iter!=pUser->pED->m_offlinesellbuffs.end();Iter++)
		{
			if(Iter->first == nSkillID)
			{
				ret = true;
			}
		}
	}

	return ret;
}

bool COfflineBuffer::IsOfflineBuffer(User *pUser)
{
	if(pUser->ValidUser())
	{
		if( (pUser->pED->nofflinesellbuffprice > 0) && (pUser->pSD->activateOfflineShopTime > 0) )
			return true;
	}

	return false;
}

bool COfflineBuffer::OfflineBufferStop(User *pUser)
{
	if(pUser->ValidUser())
	{
		if( pUser->pED->nofflinesellbuffprice > 0 )
			pUser->pED->nofflinesellbuffprice = 0;
		
		if(pUser->pSD->activateOfflineShopTime > 0)
			pUser->pSD->activateOfflineShopTime = 0;
	}

	return false;
}

int COfflineBuffer::GetBuffLevelFromUser(User *pUser, int nSkillID)
{
	if(pUser->ValidUser())
	{
		for(map<INT32, INT32>::iterator Iter = pUser->pED->m_offlinesellbuffs.begin(); Iter!=pUser->pED->m_offlinesellbuffs.end();Iter++)
		{
			if(Iter->first == nSkillID)
			{
				return Iter->second;
			}
		}
	}

	return 1;
}

void COfflineBuffer::ShowOfflineBufferList(User *pAsker, User *pBuffer, UINT page, bool isforpet)
{
	if(pAsker->ValidUser() && pBuffer->ValidUser())
	{
		const WCHAR* wHTML = g_HtmlCache.Get(L"offline_buffer_buffs.htm");
		if(wHTML)
		{
			wstring html = L"<html><head></head><body><br><br><br><center>Something gone wrong, please contact with admin!</center></body></html>";
			m_Lock.Enter();
			if(!isforpet)
			{
				if(pBuffer->pED->m_BuffPagePlayer.size() > 0 && page < pBuffer->pED->m_BuffPagePlayer.size())
				{
					html = pBuffer->pED->m_BuffPagePlayer[page];
				}
			}
			else
			{
				if(pBuffer->pED->m_BuffPagePet.size() > 0 && page < pBuffer->pED->m_BuffPagePet.size())
				{
					html = pBuffer->pED->m_BuffPagePet[page];
				}
			}
			m_Lock.Leave();

			pAsker->ShowHTML(L"offline_buffer_buffs.htm", html.c_str(), 0);
		}
	}
}

void COfflineBuffer::ShowOfflineBufferList2(User *pAsker, UINT charid, UINT page, bool isforpet)
{
	if(pAsker->ValidUser())
	{
		if(User *pBuffer = g_UserDB.GetUserByServerId(charid)->SafeCastUser())
		{
			const WCHAR* wHTML = g_HtmlCache.Get(L"offline_buffer_buffs.htm");
			if(wHTML)
			{
				wstring html = L"<html><head></head><body><br><br><br><center>Something gone wrong, please contact with admin!</center></body></html>";
				m_Lock.Enter();
				if(!isforpet)
				{
					if(pBuffer->pED->m_BuffPagePlayer.size() > 0 && page < pBuffer->pED->m_BuffPagePlayer.size())
					{
						html = pBuffer->pED->m_BuffPagePlayer[page];
					}
				}
				else
				{
					if(pBuffer->pED->m_BuffPagePet.size() > 0 && page < pBuffer->pED->m_BuffPagePet.size())
					{
						html = pBuffer->pED->m_BuffPagePet[page];
					}
				}
				m_Lock.Leave();

				pAsker->ShowHTML(L"offline_buffer_buffs.htm", html.c_str(), 0);
			}
		}
	}
}

void COfflineBuffer::BuyBuff(User *pBuyer, UINT nSkillID, UINT nSellerID, bool isforpet)
{
	if(pBuyer->ValidUser())
	{
		if(User *pSeller = User::GetUserBySID(&nSellerID))
		{
			if(CheckBuff(nSkillID) && CheckBuffExist(pSeller,nSkillID))
			{
				if(!pBuyer->pSD->nCursedOwner)
				{
					if(!pBuyer->IsInCombatMode())
					{
						if(pBuyer->IsInRange(pSeller, 250))
						{
							if(pBuyer->inventory.GetAdenaAmount() >= (int)pSeller->pED->nofflinesellbuffprice)
							{
								int nSkillLevel = GetBuffLevelFromUser(pSeller,nSkillID);
								if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(nSkillID, nSkillLevel))
								{
									//Double Abornal Time
									int NewAbnormalTime = 0;
									if(pSI->nAbnormalTime > 0)
									{
										NewAbnormalTime = pSI->nAbnormalTime * 2;
										//pSI->nAbnormalTime = NewAbnormalTime;
									}

									if(!isforpet)
									{
										pBuyer->DeleteItemInInventory(57, pSeller->pED->nofflinesellbuffprice);
										pSeller->AddItemToInventory(57, pSeller->pED->nofflinesellbuffprice);
										pBuyer->QueueBuff(pSI, false, NewAbnormalTime);
									}
									else
									{
										if(CSummon *pSummon = pBuyer->GetSummonOrPet())
										{
											pBuyer->DeleteItemInInventory(57, pSeller->pED->nofflinesellbuffprice);
											pSeller->AddItemToInventory(57, pSeller->pED->nofflinesellbuffprice);
											pBuyer->QueueBuff(pSI, true, NewAbnormalTime);
										}
										else
											pBuyer->SendSystemMessage(L"OfflineBuffer System: You don't have a pet summoned!");
									}
								}
								else
									pBuyer->SendSystemMessage(L"OfflineBuffer System: Something gone wrong, please contact with administrator!");
							}
							else
								pBuyer->SendSystemMessage(L"OfflineBuffer System: You don't have enough adena!");
						}
						else
							pBuyer->SendSystemMessage(L"OfflineBuffer System: You are too far from the seller!");
					}
					else
						pBuyer->SendSystemMessage(L"OfflineBuffer System: You cannot get buffs during a combat mode!");
				}
				else
					pBuyer->SendSystemMessage(L"OfflineBuffer System: You cannot get buffs while you armed with a cursed weapon!");
			}
		}
	}
}

void COfflineBuffer::CreatePages(User *pUser, bool isforpet)
{
	if(pUser->ValidUser())
	{
		const WCHAR* wHTML = g_HtmlCache.Get(L"offline_buffer_buffs.htm");
		if(wHTML)
		{
			wstring html(wHTML);
			//make the vars
			html = Utils::ReplaceString(html, L"<?bufferName?>", pUser->pSD->wszName, true);
			html = Utils::ReplaceString(html, L"<?bufferClass?>", g_ClassManager.GetName(pUser->pSD->nClass), true);
			html = Utils::ReplaceString(html, L"<?bufferLvl?>", pUser->pSD->nLevel, true);
			html = Utils::ReplaceString(html, L"<?buffPrice?>", pUser->pED->nofflinesellbuffprice, true);

			if(!isforpet)
				pUser->pED->m_BuffPagePlayer.clear();
			else
				pUser->pED->m_BuffPagePet.clear();

			UINT page = 0;
			UINT totalPages = static_cast<UINT>(pUser->pED->m_offlinesellbuffs.size() / 7);
			if((pUser->pED->m_offlinesellbuffs.size() % 7) != 0)
			{
				totalPages++;
			}

			wstringstream linesStream;
			bool pageFlag = true;
			UINT counter = 0;
			bool changecolor = false;

			WCHAR temp[8190] = { 0 };
			for(map<INT32, INT32>::iterator it = pUser->pED->m_offlinesellbuffs.begin(); it!=pUser->pED->m_offlinesellbuffs.end();it++)
			{
				int nSkillID = it->first;
				int nSkillLevel = it->second;
				int baseMaxLvl = g_SkillAcquireDB.GetMaxNotEnchantedSkillLevel(nSkillID);
				wstring Skillname = g_SkillDBEx.GetSkillName(nSkillID,nSkillLevel);
				wstring SkillID = Utils::IntToWString(nSkillID);
				wstring SkillLevel = Utils::IntToWString(nSkillLevel);
				wstring SkillEncPower = g_SkillDBEx.GetSkillEnch1(nSkillID,nSkillLevel);
				wstring SkillIcon = g_SkillDBEx.GetSkillIcon(nSkillID,nSkillLevel);

				pageFlag = true;
				/*----*/

				wstring line;
				line = L"<tr>";
				line += L"<td fixwidth=300>";
				if(changecolor)
					line += L"<table height=32 cellspacing=-1";
				else
					line += L"<table height=32 cellspacing=-1";
				line += L"<tr>";

				//bypass buffstore_player?skill=ID&bufferid=ID
				//bypass buffstore_pet?skill=ID&bufferid=ID
				line += L"<td width=42 valign=top><button value=\"\" action=\"bypass ";
				if(!isforpet)
					line += L"buffstore_player?skill=";
				else
					line += L"buffstore_pet?skill=";
				line += SkillID;
				line += L"&bufferid=";
				line += Utils::IntToWString(pUser->pSD->nObjectID);

				line += L"\" width=32 height=32 back=";
				line += SkillIcon;
				line += L" fore=";
				line += SkillIcon;
				line += L"></td>";
				if (nSkillLevel > baseMaxLvl)
				{
					line += L"<td fixwidth=240>";
					line += Skillname;
					line += L"<font color=a3a3a3>Lv</font> <font color=ae9978>";
					line += baseMaxLvl;
					line += L"</font>";
					line += L" <font color=ffd969>+";
					line += SkillEncPower;
					line += L"</font></td>";
				}
				else
				{
					line += L"<td fixwidth=240>";
					line += Skillname;
					line += L" <font color=a3a3a3>Lv</font> <font color=ae9978>";
					line += SkillLevel;
					line += L"</font></td>";
				}

				line += L"</tr>";
				line += L"</table>";
				line += L"</td>";
				line += L"</tr>";

				// Espacio entre cada linea de buff
				line += L"<tr>";
				line += L"<td height=10></td>";
				line += L"</tr>";

				if(!changecolor) 
					changecolor=true; 
				else if(changecolor) 
					changecolor=false; 

				/*----*/

				linesStream << line << endl;
				counter++;
				if((counter%7) == 0)
				{
					wstring templ = html;
					_itow(page, temp, 10);
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
					templ = Utils::ReplaceString(templ, L"<?buffs?>", linesStream.str(), true);
					templ = Utils::ReplaceString(templ, L"<?bufferid?>", pUser->pSD->nObjectID, true);
					if(!isforpet)
					{
						templ = Utils::ReplaceString(templ, L"<?target?>", L"Player", true);
						templ = Utils::ReplaceString(templ, L"<?target_bypass?>", L"s_buffstore_player", true);
						pUser->pED->m_BuffPagePlayer.push_back(templ);
					}
					else
					{
						templ = Utils::ReplaceString(templ, L"<?target?>", L"Pet", true);
						templ = Utils::ReplaceString(templ, L"<?target_bypass?>", L"s_buffstore_pet", true);
						pUser->pED->m_BuffPagePet.push_back(templ);
					}
					linesStream.str(L"");
					pageFlag = false;
					page++;
				}
			}
			if(pageFlag)
			{
				//add last page
				wstring templ = html;
				_itow(page, temp, 10);
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
				templ = Utils::ReplaceString(templ, L"<?buffs?>", linesStream.str(), true);
				templ = Utils::ReplaceString(templ, L"<?bufferid?>", pUser->pSD->nObjectID, true);
				if(!isforpet)
				{
					templ = Utils::ReplaceString(templ, L"<?target?>", L"Player", true);
					templ = Utils::ReplaceString(templ, L"<?target_bypass?>", L"s_buffstore_player", true);
					pUser->pED->m_BuffPagePlayer.push_back(templ);
				}
				else
				{
					templ = Utils::ReplaceString(templ, L"<?target?>", L"Pet", true);
					templ = Utils::ReplaceString(templ, L"<?target_bypass?>", L"s_buffstore_pet", true);
					pUser->pED->m_BuffPagePet.push_back(templ);
				}
				linesStream.str(L"");
				pageFlag = false;
				page++;
			}
		}
	}
}
