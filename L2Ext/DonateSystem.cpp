#include "StdAfx.h"
#include "DonateSystem.h"
#include "HtmlCache.h"
#include "PlayerAction.h"
#include "Augmentation.h"

CDonateSystem g_DonateSystem;

CDonateSystem::CDonateSystem()
{
}

CDonateSystem::~CDonateSystem()
{
}

void CDonateSystem::Init()
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

void CDonateSystem::LoadData()
{
	guard;
	ifstream file(g_ChangeFolders.DonateList_txt.c_str());
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
					CategoriesItems cai;
					m_CategoriesList.push_back(cai);
				}

			}else if(sLine.find("donate_item_start") == 0)
			{
				CDonateItem di;
				UINT catid = CParser::GetValueInt(sLine, "cat_id");
				di.catid = catid;
				di.itemid = CParser::GetValueInt(sLine, "item_id");
				di.itemquanity = CParser::GetValueInt(sLine, "item_quanity");
				di.itemenchant = CParser::GetValueInt(sLine, "item_enchant");
				di.itemaug = CParser::GetValueInt(sLine, "item_augmentation");
				di.priceid = CParser::GetValueInt(sLine, "price_id");
				di.pricequanity = CParser::GetValueInt(sLine, "price_quanity");

				if(m_CategoriesList.size() >= catid)
					m_CategoriesList[catid].m_Items.push_back(di);
			}
		}
		file.close();
	}
	unguard;
}

void CDonateSystem::CreatePages()
{
	guard;
	if(m_Enabled && (m_categories > 0) )
	{
		m_Lock.Enter();
		for(UINT n=0;n<m_CategoriesList.size();n++)
		{
			CategoriesPages cap;
			m_CategoriesPages.push_back(cap);

			const WCHAR* wHTML = g_HtmlCache.Get(L"donate_show.htm");
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
								CDonateItem& cap = m_CategoriesList[n].m_Items[i];
								cat_id = cap.catid;
								pageFlag = true;
								wstring line = templateLine;

								if( place == 0 || place == 2 || place == 4 || place == 6 || place == 8)
									line = Utils::ReplaceString(line, L"<?bgcolor?>", L"bgcolor=\"000000\"", true);
								else
									line = Utils::ReplaceString(line, L"<?bgcolor?>", L"", true);

								line = Utils::ReplaceString(line, L"<?p_itemicon?>", g_ItemDBEx.GetItemIcon(cap.itemid), true);

								wstringstream itemname;
								itemname << L"<a action=\"bypass -h don_item?cat=" << cap.catid << L"&item=" << i << L"\">" << g_ItemDBEx.GetItemName(cap.itemid) << L"</a>";

								wstringstream itemsa;
								itemsa << L"<font color=LEVEL>" << g_ItemDBEx.GetItemSA(cap.itemid) << L" </font>";
								line = Utils::ReplaceString(line, L"<?p_itemsa?>", itemsa.str().c_str(), true);
								line = Utils::ReplaceString(line, L"<?p_itemname?>", itemname.str().c_str(), true);
								line = Utils::ReplaceString(line, L"<?p_itemprice?>", cap.pricequanity, true);
								line = Utils::ReplaceString(line, L"<?p_itempriceid?>", g_ItemDBEx.GetItemName(cap.priceid), true);

								if(cap.itemenchant > 0)
								{
									wstringstream enchant;
									enchant << L"<font color=LEVEL>+" << cap.itemenchant << L" </font>";
									line = Utils::ReplaceString(line, L"<?p_itemencant?>", enchant.str().c_str(), true);
								}
								else
									line = Utils::ReplaceString(line, L"<?p_itemencant?>", L"", true);
										
								if( cap.itemaug > 0 )
									line = Utils::ReplaceString(line, L"<?p_itemaug?>", L"[A]", true);
								else
									line = Utils::ReplaceString(line, L"<?p_itemaug?>", L"", true);

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
				g_Log.Add(CLog::Error, "[%s] Cannot find html - donate_show.htm !", __FUNCTION__);
			}
		}
		m_Lock.Leave();
	}
	unguard;
}

void CDonateSystem::RequestShowCategory(User *pUser, UINT category, UINT page)
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

		PlayerAction::ShowHTML(pUser, L"donate_show.htm", html.c_str(), 0);
	}
	unguard;
}

void CDonateSystem::RequestShowItem(User *pUser, UINT category, UINT item)
{
	guard;
	if(m_Enabled)
	{
		wstring html1 = L"<html><head></head><body><br><br><br><center>Loading data...<br>Please try again later...</center></body></html>";
		m_Lock.Enter();
		if(m_CategoriesList.size() > 0 && category < m_CategoriesList.size())
		{
			if( (m_CategoriesList[category].m_Items.size() > 0) && (m_CategoriesList[category].m_Items.size() > item) )
			{
				const WCHAR* wHTML = g_HtmlCache.Get(L"donate_item_show.htm");
				if(wHTML)
				{
					wstring html(wHTML);

					CDonateItem& cdi = m_CategoriesList[category].m_Items[item];

					html = Utils::ReplaceString(html, L"<?p_itemicon?>", g_ItemDBEx.GetItemIcon(cdi.itemid), true);
										
					html = Utils::ReplaceString(html, L"<?cat?>", cdi.catid, true);
					wstringstream bypass;
					bypass << L"bypass -h bs_buy_item?priceId=" << cdi.priceid << L"&priceAmount=" << cdi.pricequanity << L"&rewardId=" << cdi.itemid << L"&rewardAmount=" << cdi.itemquanity<< L"&rewardEnchant=" << cdi.itemenchant;
					html = Utils::ReplaceString(html, L"<?p_bypass?>", bypass.str().c_str(), true);

					html = Utils::ReplaceString(html, L"<?p_itemname?>", g_ItemDBEx.GetItemName(cdi.itemid), true);
					wstringstream itemsa;
					itemsa << L"<font color=LEVEL>" << g_ItemDBEx.GetItemSA(cdi.itemid) << L" </font>";
					html = Utils::ReplaceString(html, L"<?p_itemsa?>", itemsa.str().c_str(), true);
					html = Utils::ReplaceString(html, L"<?p_itemprice?>", cdi.pricequanity, true);
					html = Utils::ReplaceString(html, L"<?p_itempriceid?>", g_ItemDBEx.GetItemName(cdi.priceid), true);

					if(cdi.itemenchant > 0)
					{
						wstringstream enchant;
						enchant << L"<font color=LEVEL>+" << cdi.itemenchant << L" </font>";
						html = Utils::ReplaceString(html, L"<?p_itemencant?>", enchant.str().c_str(), true);
					}
					else
						html = Utils::ReplaceString(html, L"<?p_itemencant?>", L"", true);
												
					if( cdi.itemaug > 0 )
					{
						html = Utils::ReplaceString(html, L"<?p_aug1?>", g_Augmentation.GetName(g_Augmentation.GetFirstEffectID(cdi.itemaug)), true);
						html = Utils::ReplaceString(html, L"<?p_aug2?>", g_Augmentation.GetName(g_Augmentation.GetSecondEffectID(cdi.itemaug)), true);
					}
					else
					{
						html = Utils::ReplaceString(html, L"<?p_aug1?>", L"None", true);
						html = Utils::ReplaceString(html, L"<?p_aug2?>", L"None", true);
					}

					html1 = html;
				}

			}
		}
		m_Lock.Leave();

		PlayerAction::ShowHTML(pUser, L"donate_item_show.htm", html1.c_str(), 0);
	}
	unguard;
}




