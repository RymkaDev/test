#include "StdAfx.h"
#include "DonateAugment.h"
#include "HtmlCache.h"
#include "PlayerAction.h"
#include "Augmentation.h"
#include "DB.h"

CDonateSystemAugment g_DonateSystemAugment;

CDonateSystemAugment::CDonateSystemAugment()
{
}

CDonateSystemAugment::~CDonateSystemAugment()
{
}

void CDonateSystemAugment::Init()
{
	guard;
	m_Lock.Enter();
	m_Enabled = false;
	m_categories = 0;
	m_CategoriesList.clear();
	m_CategoriesPages.clear();
	LoadData();
	CreatePages();

	if(m_Enabled)
	{
		UINT totalitems = 0;
		UINT totalpages = 0;

		for(int n=0; n<m_CategoriesList.size(); n++)
		{
			totalitems = totalitems + m_CategoriesList[n].m_Items.size();
		}

		for(int i=0; i<m_CategoriesPages.size(); i++)
		{
			totalpages = totalpages + m_CategoriesPages[i].m_Pages.size();
		}

		g_Log.Add(CLog::Blue, "[%s] Feature is enabled. Loaded Categories[%d], Items[%d], Pages[%d].", __FUNCTION__, m_CategoriesList.size(), totalitems, totalpages); //mistake here

	}
	m_Lock.Leave();
	unguard;
}

void CDonateSystemAugment::LoadData()
{
	guard;
	ifstream file(g_ChangeFolders.DonateAugmentList_txt.c_str());
	if(file)
	{
		string sLine;
		while(getline(file, sLine))
		{
			//setting_bein	enabled=1	categories=2	setting_end
			if(sLine.find("//") == 0)
				continue;
			if(sLine.find("setting_begin") == 0)
			{
				m_Enabled = CParser::GetValueInt(sLine, "enabled");
				m_categories = CParser::GetValueInt(sLine, "categories");

				for(UINT n=0;n<m_categories;n++)
				{
					CategoriesItemsAugment cai;
					m_CategoriesList.push_back(cai);
				}

			}else if(sLine.find("donate_item_start") == 0)
			{
				CDonateItemAugment dia;
				UINT catid = CParser::GetValueInt(sLine, "cat_id");
				dia.catid = catid;
				dia.augmentid = CParser::GetValueInt(sLine, "augment_id");
				dia.priceid = CParser::GetValueInt(sLine, "price_id");
				dia.pricequanity = CParser::GetValueInt(sLine, "price_quanity");

				if(m_CategoriesList.size() >= catid)
					m_CategoriesList[catid].m_Items.push_back(dia);
			}
		}
		file.close();
	}
	unguard;
}

void CDonateSystemAugment::CreatePages()
{
	guard;
	if(m_Enabled && (m_categories > 0) )
	{
		m_Lock.Enter();
		for(UINT n=0;n<m_CategoriesList.size();n++)
		{
			CategoriesPagesAugment cap;
			m_CategoriesPages.push_back(cap);

			const WCHAR* wHTML = g_HtmlCache.Get(L"donate_augment_show.htm");
			if(wHTML)
			{
				if(m_CategoriesList[n].m_Items.size() > 0)
				{
					wstring html(wHTML);
					//m_PagesPvP.clear();
					m_CategoriesPages[n].m_Pages.clear();

					UINT page = 0;
					UINT totalPages = static_cast<UINT>(m_CategoriesList[n].m_Items.size() / 8);
					if((m_CategoriesList[n].m_Items.size() % 8) != 0)
					{
						totalPages++;
					}
					WCHAR temp[8190] = { 0 };
					UINT cat_id = 0;
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
							for(UINT i=0;i<m_CategoriesList[n].m_Items.size();i++)
							{
								CDonateItemAugment& cap = m_CategoriesList[n].m_Items[i];
								cat_id = cap.catid;
								pageFlag = true;
								wstring line = templateLine;

								if( place == 0 || place == 2 || place == 4 || place == 6 || place == 8)
									line = Utils::ReplaceString(line, L"<?bgcolor?>", L"bgcolor=\"000000\"", true);
								else
									line = Utils::ReplaceString(line, L"<?bgcolor?>", L"", true);

								//

								//g_SkillDBEx.GetSkillIcon(int nSkillID, int nSkillLev)

								wstringstream skillicon;
								if(g_Augmentation.IsSkill(cap.augmentid))
								{
									AugmentSkill as = g_Augmentation.GetAugmentSkill(cap.augmentid);
									skillicon << g_SkillDBEx.GetSkillIcon(as.nSkillID, as.nLevel);
								}

								line = Utils::ReplaceString(line, L"<?p_itemicon?>", skillicon.str().c_str() , true);

								wstringstream itemname;
								itemname << L"<a action=\"bypass -h don_augm_item?cat=" << cap.catid << L"&augm=" << cap.augmentid << L"\">" << g_Augmentation.GetName(cap.augmentid) << L"</a>";

								line = Utils::ReplaceString(line, L"<?p_itemname?>", itemname.str().c_str(), true);
								

								line = Utils::ReplaceString(line, L"<?p_itemprice?>", cap.pricequanity, true);
								line = Utils::ReplaceString(line, L"<?p_itempriceid?>", g_ItemDBEx.GetItemName(cap.priceid), true);

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
									templ = Utils::ReplaceString(templ, L"<?cat?>", cat_id, true);
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
									//m_PagesPvP.push_back(templ);
									m_CategoriesPages[n].m_Pages.push_back(templ);
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
								templ = Utils::ReplaceString(templ, L"<?cat?>", cat_id, true);
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
								//m_PagesPvP.push_back(templ);
								m_CategoriesPages[n].m_Pages.push_back(templ);
								linesStream.str(L"");
								pageFlag = false;
								page++;
								place = 0;
							}
						}
					}
				}
			}else
			{
				g_Log.Add(CLog::Error, "[%s] Cannot find html - donate_augment_show.htm !", __FUNCTION__);
			}
		}
		m_Lock.Leave();
	}
	unguard;
}

void CDonateSystemAugment::RequestShowCategory(User *pUser, UINT category, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...</center></body></html>";
		m_Lock.Enter();
		if(m_CategoriesPages.size() > 0 && category < m_CategoriesPages.size())
		{
			if( (m_CategoriesPages[category].m_Pages.size() > 0) && (m_CategoriesPages[category].m_Pages.size() > page) )
			{
				html = m_CategoriesPages[category].m_Pages[page];
			}
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"donate_augment_show.htm", html.c_str(), 0);
	}
	unguard;
}

void CDonateSystemAugment::RequestShowUserWeapons(User *pUser, UINT page)
{
	guard;
	if(m_Enabled)
	{
		wstring html = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...</center></body></html>";
		pUser->pED->lockDonateAugment.Enter();
		if(pUser->pED->m_PagesAugmentDonation.size() > 0 && page < pUser->pED->m_PagesAugmentDonation.size())
		{
			html = pUser->pED->m_PagesAugmentDonation[page];
		}
		pUser->pED->lockDonateAugment.Leave();

		PlayerAction::ShowHTML(pUser, L"donate_augment_show_weps.htm", html.c_str(), 0);
	}
	unguard;
}

bool CDonateSystemAugment::AugmentExistOnDonationList(User *pUser, UINT category, UINT augment)
{
	guard;
	m_Lock.Enter();
	if( (m_CategoriesList.size() >= category) && (category >= 0) )
	{
		if(m_CategoriesList[category].m_Items.size() > 0)
		{
			bool bFound = false;
			for(UINT i=0;i<m_CategoriesList[category].m_Items.size();i++)
			{
				CDonateItemAugment& cap = m_CategoriesList[category].m_Items[i];

				if(cap.augmentid == augment)
					bFound = true;
			}
			m_Lock.Leave();
			unguard;
			return bFound;
		}
		else
		{
			g_Log.Add(CLog::Error, "[%s] User[%s] tried to buy augment on empty category id[%d]", __FUNCTION__, pUser->pSD->wszName, category);
			m_Lock.Leave();
			unguard;
			return false;
		}
	}
	else
	{
		g_Log.Add(CLog::Error, "[%s] User[%S] sended invalid category id[%d] total lists:[%d]", __FUNCTION__, pUser->pSD->wszName, category, m_CategoriesList.size());
		m_Lock.Leave();
		unguard;
		return false;
	}
	m_Lock.Leave();
	unguard;
	return false;
}

//CItem *pWeapon = pUser->GetInventory()->GetItemBySID(nWeaponSID)->GetWeapon();
void CDonateSystemAugment::RequestShowItems(User *pUser, UINT category, UINT augment)
{
	guard;
	if(m_Enabled)
	{
		if(pUser->ValidUser())
		{
			//Check if Category & augment is valid
			if(AugmentExistOnDonationList(pUser, category, augment))
			{
				//List all weapons without augment
				CSharedItemData* lpSharedItemDataArray = (*(CSharedItemData**)0x0E412138);
				INT32 itemCount = 0;
				CItem *pItem;

				pUser->pED->lockDonateAugment.Enter();
				pUser->pED->m_DonateItemsAugment.clear();

				pUser->inventory.ReadLock(__FILEW__, __LINE__);
				INT32 index = pUser->inventory.GetFirstItemIndex();
				try
				{
					while(index > -1 && index < 900000 && itemCount < 200)
					{
						CSharedItemData *lpSID = &lpSharedItemDataArray[index];
						if(lpSID)
						{
							if(pItem = pUser->inventory.GetItemByIndex(index))
							{
								if(pItem->IsValid(VT_ITEMWEAPON))
								{
									if( pItem->nAugmentationID == 0 )
									{
										DonateAugmentWeapons daw;
										daw.nDBid = pItem->pSID->nDBID;
										daw.nItemID = pItem->pSID->nItemID;
										daw.nEnchant = pItem->pSID->nEnchantLevel;
										
										pUser->pED->m_DonateItemsAugment.push_back(daw);
									}
								}
							}
						}
						index = lpSID->nNextIndex;
						itemCount++;
					}
										
				}catch(...)
				{
					EXCEPTION_LOG;
				}
				pUser->inventory.ReadUnlock();
				pUser->pED->lockDonateAugment.Leave();

				//Build the weapon list for user
				pUser->pED->lockDonateAugment.Enter();
				const WCHAR* wHTML = g_HtmlCache.Get(L"donate_augment_show_weps.htm");
				if(wHTML)
				{
					if(pUser->pED->m_DonateItemsAugment.size() > 0)
					{
						wstring html(wHTML);
						//m_PagesPvP.clear();
						pUser->pED->m_PagesAugmentDonation.clear();

						UINT page = 0;
						UINT totalPages = static_cast<UINT>(pUser->pED->m_DonateItemsAugment.size() / 8);
						if((pUser->pED->m_DonateItemsAugment.size() % 8) != 0)
						{
							totalPages++;
						}
						WCHAR temp[8190] = { 0 };
						UINT cat_id = 0;
						size_t startPos = html.find(L"<template_line>");
						wstring templateLine, templateLineEx;
						if(startPos != wstring::npos)
						{
							size_t endPos = html.find(L"</template_line>", startPos);
							if(endPos != wstring::npos)
							{
								templateLineEx = html.substr(startPos, (endPos + 16 - startPos));
								templateLine = html.substr(startPos + 15, (endPos - startPos - 15));

								wstringstream linesStream;
								bool pageFlag = true;
								UINT counter = 0;
								UINT place = 0;
								for(UINT i=0;i<pUser->pED->m_DonateItemsAugment.size();i++)
								{
									DonateAugmentWeapons& daw = pUser->pED->m_DonateItemsAugment[i];
									pageFlag = true;
									wstring line = templateLine;

									if( place == 0 || place == 2 || place == 4 || place == 6 || place == 8)
										line = Utils::ReplaceString(line, L"<?bgcolor?>", L"bgcolor=\"000000\"", true);
									else
										line = Utils::ReplaceString(line, L"<?bgcolor?>", L"", true);

									line = Utils::ReplaceString(line, L"<?p_itemicon?>", g_ItemDBEx.GetItemIcon(daw.nItemID), true);

									wstringstream itemsa;
									itemsa << L"<font color=LEVEL>" << g_ItemDBEx.GetItemSA(daw.nItemID) << L" </font>";
									line = Utils::ReplaceString(line, L"<?p_itemsa?>", itemsa.str().c_str(), true);

									wstringstream itemname;
									itemname << L"<a action=\"bypass -h don_augm_buy?catid=" << category << L"&itemid=" << daw.nDBid << L"&augm=" << augment << L"\">" << g_ItemDBEx.GetItemName(daw.nItemID) << L"</a>";

									line = Utils::ReplaceString(line, L"<?p_itemname?>", itemname.str().c_str(), true);
									
									if(daw.nEnchant > 0)
									{
										wstringstream enchant;
										enchant << L"<font color=LEVEL>+" << daw.nEnchant << L" </font>";
										line = Utils::ReplaceString(line, L"<?p_itemencant?>", enchant.str().c_str(), true);
									}
									else
										line = Utils::ReplaceString(line, L"<?p_itemencant?>", L"", true);

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
										templ = Utils::ReplaceString(templ, L"<?cat?>", cat_id, true);
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
										pUser->pED->m_PagesAugmentDonation.push_back(templ);
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
									templ = Utils::ReplaceString(templ, L"<?cat?>", cat_id, true);
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
									//m_PagesPvP.push_back(templ);
									pUser->pED->m_PagesAugmentDonation.push_back(templ);
									linesStream.str(L"");
									pageFlag = false;
									page++;
									place = 0;
								}
							}
						}
					}
				}else
				{
					g_Log.Add(CLog::Error, "[%s] Cannot find html - donate_augment_show_weps.htm !", __FUNCTION__);
				}
				pUser->pED->lockDonateAugment.Leave();

			}

			RequestShowUserWeapons(pUser, 0);
		}
	}
	unguard;
}

void CDonateSystemAugment::RequestBuyAugment(User *pUser, UINT category, UINT itemid, UINT augment)
{
	guard;
	if(m_Enabled)
	{
		if(pUser->ValidUser())
		{
			//Check if Category & augment is valid
			if(AugmentExistOnDonationList(pUser, category, augment) && (itemid > 0) )
			{
				if(CItem *pWeapon = pUser->inventory.GetItemByDBID(itemid))
				{
					if(pWeapon->nAugmentationID == 0 && pWeapon->IsValid(VT_ITEMWEAPON) )
					{
						bool nCheckRequirments = true;

						if(pUser->pSD->bGuilty || pUser->IsInCombatMode())
						{
							nCheckRequirments = false;
							pUser->SendSystemMessageRed(L"You cannot buy augment on your weapon during combat mode!");
						}

						if(pUser->pSD->nKarma)
						{
							nCheckRequirments = false;
							pUser->SendSystemMessageRed(L"You cannot buy augment on your weapon while your have karma!");
						}

						if( pUser->olympiadUser.IsInside() || pUser->pED->tvtUser.status == TvT::UserFighting )
						{
							nCheckRequirments = false;
							pUser->SendSystemMessageRed(L"You cannot buy augment on your weapon during olympiad or tvt fights!");
						}

						if(!pUser->inPeaceZone)
						{
							nCheckRequirments = false;
							pUser->SendSystemMessageRed(L"You can buy augment on your weapon only inside peace zone!");
						}

						if(CSummon *pSummon = pUser->GetSummonOrPet())
						{
							nCheckRequirments = false;
							pUser->SendSystemMessageRed(L"You cannot buy augment on your weapon while having pet or summon alive!");
						}

						if(nCheckRequirments)
						{
							if(pUser->IsNowTrade())
								pUser->TradeCancel();

							//Get augment info
							bool bFound = false;
							CDonateItemAugment cap;
							m_Lock.Enter();
							if( (m_CategoriesList.size() >= category) && (category >= 0) )
							{
								if(m_CategoriesList[category].m_Items.size() > 0)
								{
									for(int i=0; i<m_CategoriesList[category].m_Items.size(); i++)
									{
										if(m_CategoriesList[category].m_Items[i].augmentid == augment)
										{
											cap = m_CategoriesList[category].m_Items[i];
											
											bFound = true;
											break;
										}
									}
								}
							}
							m_Lock.Leave();

							if(bFound)
							{
								//generate first augment random
								UINT nAugmentIdRandom = g_Augmentation.GenerateAugmentation(3, 76, 0);

								UINT nFirstEffect =  0x0000FFFF&nAugmentIdRandom;
								UINT nSecondEffect = nAugmentIdRandom >> 16;

								UINT nAugmentationFinal = (augment << 16)+nFirstEffect;

								bool bHasPrice = false;
								if( (cap.priceid > 0) && (cap.pricequanity > 0) ) 
									bHasPrice = true;


								bool bPricePaid = true;
								if( bHasPrice && !pUser->DeleteItemInInventory(cap.priceid, cap.pricequanity))
									bPricePaid = false;

								if(bPricePaid)
								{
									pWeapon->nAugmentationID = nAugmentationFinal;
									g_DB.RequestSaveItemDataEx(pUser->nDBID, pWeapon);
									pUser->inventory.SetInventoryChanged(pWeapon, 2);
									pUser->SendSystemMessageGreen(L"Your item augmentated successfully!");
									g_Logger.Add(L"User[%s] augment weapon[%d] BY DONATE dbid[%d] firstEffet[RANDOM] secondEffect[%d]", pUser->pSD->wszName, pWeapon->pSID->nItemID, pWeapon->nDBID, augment);
								}
								else
								{
									pUser->SendSystemMessageRed(L"You don't have the required items for this action!");
								}

							}
						}
					}
				}
			}
		}
	}

	unguard;
}