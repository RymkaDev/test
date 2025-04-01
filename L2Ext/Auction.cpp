#include "stdafx.h"
#include "Auction.h"
#include "HtmlCache.h"
#include "Augmentation.h"
#include "DB.h"

CAuction g_Auction;

CAuction::CAuction() : m_Enabled(FALSE), m_ExpireTimestamp(0)
{

}

CAuction::~CAuction()
{
}

void CAuction::Init()
{
	LoadINI();
	if(m_Enabled)
	{
		g_DB.RequestLoadAuctionItems();
	}
}

/*
[Auction]
;In order to work properly ItemDelivery Feature need to be enabled too. (Recomend Check Time 60 sec)
Enabled=1
;Duration of an auction in seconds (default: 172800 - 2 days / 0 Unlimited)
AuctionTime=172800
;Auction Fee that User has to pay in order to place an item into Auction House
AuctionFeeID=57
AuctionFee=5000
;Max amount of non stackable items sold by 1 player at the same time
AuctionLimit=10
;Sell Curencies
SellCurrencyCount=2
SellCurrencyId_1=57
SellCurrencyName_1=Adena
SellCurrencyHtml_1=<font color=LEVEL>[A]</font>
SellCurrencyId_2=57
SellCurrencyName_2=Donation Coin
SellCurrencyHtml_2=<font color=F6CEF5>[DC]</font>
;Auction House will be aviable only into Peace Zones
PeaceModeOnly=1
;Auction House Buy/Sell Functions will not be avilable on players with Karma
KarmaDisable=1
*/

void CAuction::LoadINI()
{
	const TCHAR* section = _T("Auction");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), FALSE, g_ConfigFile);
	m_AuctionTime = GetPrivateProfileInt(section, _T("AuctionTime"), 172800, g_ConfigFile);
	m_AuctionFeeID = GetPrivateProfileInt(section, _T("AuctionFeeID"), 57, g_ConfigFile);
	m_AuctionFee = GetPrivateProfileInt(section, _T("AuctionFee"), 10000, g_ConfigFile);
	m_AuctionFeeDel = GetPrivateProfileInt(section, _T("AuctionFeeDelete"), 1, g_ConfigFile);
	m_AuctionLimit = GetPrivateProfileInt(section, _T("AuctionLimit"), 10, g_ConfigFile);
	m_PeaceMode = GetPrivateProfileInt(section, _T("PeaceMode"), 1, g_ConfigFile); //TODO
	m_KarmaDisable = GetPrivateProfileInt(section, _T("KarmaDisable"), 1, g_ConfigFile); //TODO
	m_CacheDelay = GetPrivateProfileInt(section, _T("CacheDelay"), 120, g_ConfigFile); //TODO

	TCHAR temp[0x10000] = { 0 };
	UINT nSellCurrencyCount = GetPrivateProfileInt(section, _T("SellCurrencyCount"), 0, g_ConfigFile);

	m_SellCurrency.clear();
	if(nSellCurrencyCount > 0)
	{
		for(UINT n=1; n <= nSellCurrencyCount; n++)
		{
			SellCurrency sc;
			tstringstream sectionEx1;
			sectionEx1 << "SellCurrencyId_" << n ;
			sc.itemId = GetPrivateProfileInt(section, sectionEx1.str().c_str(), 0, g_ConfigFile);
			tstringstream sectionEx2;
			sectionEx2 << "SellCurrencyName_" << n ;
			GetPrivateProfileString(section, sectionEx2.str().c_str(), 0, temp, 0x10000, g_ConfigFile);
			sc.itemName = temp;
			tstringstream sectionEx3;
			sectionEx3 << "SellCurrencyHtml_" << n ;
			GetPrivateProfileString(section, sectionEx3.str().c_str(), 0, temp, 0x10000, g_ConfigFile);
			sc.htmlstring = temp;

			//g_Log.Add(CLog::Blue, "[%s] Sell CurrencyID[%d] Name[%s], html[%S]!", __FUNCTION__, sc.itemId, sc.itemName.c_str(), sc.htmlstring.c_str());

			m_SellCurrency.insert(pair<UINT, SellCurrency>(sc.itemId, sc));
		}
	}
}

void CAuction::TimerExpired()
{
	guard;

	if(m_Enabled)
	{
		if(m_ExpireTimestamp < time(0))
		{
			m_ExpireTimestamp = time(0) + 120;

			m_Lock.Enter();
			for(map<UINT, AuctionItem>::iterator it = m_Items.begin(); it!= m_Items.end(); it++)
			{
				AuctionItem& ai = it->second;
				if( (ai.auctionTimeoutTime != 0) && (ai.auctionTimeoutTime < time(0)) )
				{
					//Send the item back to the owner
					//TODO
				}
			}
			m_Lock.Leave();
		}
	}

	unguard;
}

void CAuction::GetUserItemList(User *pUser)
{
	guard;

	CSharedItemData* lpSharedItemDataArray = (*(CSharedItemData**)0x0E412138);
	INT32 itemCount = 0;
	pUser->pED->lockAuction.Enter();
	pUser->pED->m_ItemAuctionList.clear();
	pUser->pED->lockAuction.Leave();

	pUser->inventory.ReadLock(__FILEW__, __LINE__);
	INT32 index = pUser->inventory.GetFirstItemIndex();
	try
	{
		while(index > -1 && index < 900000 && itemCount < 200)
		{
			CSharedItemData *lpSID = &lpSharedItemDataArray[index];
			if(lpSID)
			{
				if(CItem *pItem = pUser->inventory.GetItemByIndex(index))
				{
					if(pItem->IsValidItem())
					{
						if(g_ItemDBEx.ItemCanBeSold(pItem->pSID->nItemID) /*&& (pItem->nAugmentationID == 0)*/ ) //temp augm TODO
						{
							AuctionItemList ai;
							ai.itemDBId = pItem->pSID->nDBID;
							//ai.itemAugmentation = Augmentation(pItem->nAugmentationID);
							ai.itemAugmentation = pItem->nAugmentationID;
							ai.itemAmount = pItem->pSID->nItemAmount;
							ai.itemClassId = pItem->pSID->nItemID;
							ai.itemEnchant = pItem->pSID->nEnchantLevel;
							ai.pInfo = g_ItemDBEx.GetItemInfo(pItem->pSID->nItemID);

							pUser->pED->lockAuction.Enter();
							pUser->pED->m_ItemAuctionList.push_back(ai);
							pUser->pED->lockAuction.Leave();
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

	unguard;
}

void CAuction::CacheItemsMe(User *pUser, bool forceupdate)
{
	guard;

	if(pUser->pED->m_AuctionExpireMy < time(0) || forceupdate)
	{
		m_Lock.Enter();
		pUser->pED->lockAuction.Enter();
		pUser->pED->m_AuctionItemsMy.clear();
		int n = 0;
		for(map<UINT, AuctionItem>::iterator it = m_Items.begin(); it!= m_Items.end(); it++)
		{
			if(it->second.sellerDatabaseId == pUser->pSD->nDBID)
			{
				pUser->pED->m_AuctionItemsMy.insert(pair<UINT, AuctionItem>(n, it->second));
				n++;
			}
		}
		pUser->pED->m_TotalAuctions = pUser->pED->m_AuctionItemsMy.size();
		pUser->pED->m_AuctionExpireMy = time(0) + m_CacheDelay;
		pUser->pED->lockAuction.Leave();
		m_Lock.Leave();
	}

	unguard;
}

bool CAuction::RequestShowAuctionMe(User *pUser, UINT page, UINT page2, UINT nItemDbID, bool forceupdate)
{
	guard;
	if(m_Enabled && pUser->ValidUser())
	{
		const WCHAR *wHtml = g_HtmlCache.Get(L"auction_show_my.htm");
		if(wHtml)
		{
			wstring html(wHtml);

			//here tempalte for items on char
			GetUserItemList(pUser);

			pUser->pED->lockAuction.Enter();
			UINT start_pos = 0;
			if( page2 == 0 ) 
				start_pos = 0;
			else if( page2 > 0 )
				start_pos = 5 * page2;

			UINT m_UserListSize = pUser->pED->m_ItemAuctionList.size();
			UINT m_ItemsToAdd = 20;
			if( (start_pos + m_ItemsToAdd) > m_UserListSize )
			{
				m_ItemsToAdd = m_UserListSize - start_pos;
			}

			for(UINT m=0; m < 20; m++ )
			{
				UINT pos = m + start_pos;
				UINT nButtonNumber = m + 1;

				if( m + start_pos < m_UserListSize )
				{

					wstringstream ButtonToAdd;
					ButtonToAdd << L"<button value=\"\" action=\"bypass _auction_me?pag2=" << page2 << L"&item=" << pUser->pED->m_ItemAuctionList[pos].itemDBId << "\" width=32 height=32 back=\"" << g_ItemDBEx.GetItemIcon(pUser->pED->m_ItemAuctionList[pos].itemClassId) << L"\" fore=\"" << g_ItemDBEx.GetItemIcon(pUser->pED->m_ItemAuctionList[pos].itemClassId) << L"\">";

					wstringstream NumberButton;
					NumberButton << L"<?but" << nButtonNumber << L"?>";
					html = Utils::ReplaceString(html, NumberButton.str(), ButtonToAdd.str(), true);
				}
				else
				{
					wstringstream NumberButton;
					NumberButton << L"<?but" << nButtonNumber << L"?>";
					html = Utils::ReplaceString(html, NumberButton.str(), L"", true);
				}
			}
			
			//Count Pages
			UINT m_ListSizeLines = (m_UserListSize-20) / 5 + 1;

			UINT next_page = 0;
			if( page2 >= m_ListSizeLines )
				next_page = m_ListSizeLines;
			else
				next_page = page2+1;

			html = Utils::ReplaceString(html, L"<?next_page_list?>", next_page, true);

			UINT prev_page = 0;
			if( page2 == 0 )
				prev_page = 0;
			else
				prev_page = page2-1;

			html = Utils::ReplaceString(html, L"<?prev_page_list?>", prev_page, true);

			html = Utils::ReplaceString(html, L"<?total_page_list?>", (int)m_ListSizeLines, true);

			//TODO if nItemDbID -> item selected
			if(nItemDbID > 0)
			{
				CItem *pItem = pUser->inventory.GetItemByDBID(nItemDbID);
				if(pItem)
				{
					//pItem->pSID->nItemID
					wstringstream SellArea;
					SellArea << L"<table width=215 height=37 bgcolor=000000 border=0 cellpadding=0 cellspacing=0>";
					SellArea << L"<tr>";
					SellArea << L"	<td width=5 height=34></td>";
					SellArea << L"	<td width=34 height=34><img src=\"" << g_ItemDBEx.GetItemIcon(pItem->pSID->nItemID) << L"\" width=32 height=32></td>";
					SellArea << L"	<td width=5 height=34></td>";
					if(pItem->pSID->nEnchantLevel > 0)
					{
						SellArea << L"	<td width=171 height=34> +"<< Utils::IntToWString(pItem->pSID->nEnchantLevel) << L" " << g_ItemDBEx.GetItemName(pItem->pSID->nItemID) << L"<br1><font color=LEVEL>" << g_ItemDBEx.GetItemSA(pItem->pSID->nItemID) << L"</font></td>";
					}else
					{
						SellArea << L"	<td width=171 height=34>"<< g_ItemDBEx.GetItemName(pItem->pSID->nItemID) << L"<br1><font color=LEVEL>" << g_ItemDBEx.GetItemSA(pItem->pSID->nItemID) << L"</font></td>";
					}					
					SellArea << L"</tr>";

					SellArea << L"</table>";
					SellArea << L"<br>";
					SellArea << L"<table width=215 bgcolor=000000 border=0 cellpadding=0 cellspacing=0>";
					SellArea << L"<tr>";
					SellArea << L"	<td width=107 height=20 align=center></td>";
					SellArea << L"	<td width=108 height=20 align=center></td>";
					SellArea << L"</tr>";

					if(pItem->pSID->nItemAmount > 1)
					{
						SellArea << L"<tr>";
						SellArea << L"	<td width=107 height=25 align=center>Quantity:</td>";
						SellArea << L"	<td width=108 height=25 align=center>" << Utils::FormatWithCommas(pItem->pSID->nItemAmount) << L"</td>";
						SellArea << L"</tr>";
						SellArea << L"<tr>";
						SellArea << L"	<td width=107 height=25 align=center>Amount:</td>";
						SellArea << L"	<td width=108 height=25 align=center><edit type=\"number\" var=\"amount\" height=12 width=100></td>";
						SellArea << L"</tr>";
					}
					else
					{
						SellArea << L"<tr>";
						SellArea << L"	<td width=107 height=25 align=center>Amount:</td>";
						SellArea << L"	<td width=108 height=25 align=center>1</td>";
						SellArea << L"</tr>";
					}

					SellArea << L"<tr>";
					SellArea << L"	<td width=107 height=25 align=center>Currency:</td>";

					wstringstream PriceAsk;
					int n=0;
					for(map<UINT, SellCurrency>::iterator it = m_SellCurrency.begin(); it != m_SellCurrency.end(); it++)
					{
						n++;
						SellCurrency& sc = it->second;
						PriceAsk << sc.itemName;
						if( n != m_SellCurrency.size())
							PriceAsk << L";";
					}
					SellArea << L"	<td width=108 height=25 align=center><combobox width=100 height=12 var=\"price_ask\" list=\"" << PriceAsk.str() << "\"></td>";
					SellArea << L"</tr>";

					SellArea << L"<tr>";
					SellArea << L"	<td width=107 height=25 align=center>Price Per Item:</td>";
					SellArea << L"	<td width=108 height=25 align=center><edit type=\"number\" var=\"price_item\" height=12 width=100></td>";
					SellArea << L"</tr>";
					SellArea << L"<tr>";
					SellArea << L"	<td width=107 height=25 align=center>Sale Fee:</td>";
					SellArea << L"	<td width=108 height=25 align=center>" << Utils::FormatWithCommas(m_AuctionFee) << L"</td>";
					SellArea << L"</tr>";
					SellArea << L"</table>";
					SellArea << L"<table width=215 bgcolor=000000 height=25 border=0 cellpadding=0 cellspacing=0>";
					SellArea << L"<tr>";

					if(pItem->pSID->nItemAmount > 1)
					{
						SellArea << L"	<td><center><button value=\"Start Auction\" action=\"bypass _auction_set_con_item?id=" << Utils::IntToWString(nItemDbID) << L"&amount= $amount &priceid = $price_ask &price= $price_item \" width=95 height=21 back=\"l2ui_ch3.bigbutton_down\" fore=\"l2ui_ch3.bigbutton\"></center></td>";
					}
					else
					{
						SellArea << L"	<td><center><button value=\"Start Auction\" action=\"bypass _auction_set_con_item?id=" <<  Utils::IntToWString(nItemDbID) << L"&amount=1&priceid = $price_ask &price= $price_item \" width=95 height=21 back=\"l2ui_ch3.bigbutton_down\" fore=\"l2ui_ch3.bigbutton\"></center></td>";
					}
					SellArea << L"</tr>";
					SellArea << L"</table>";

					html = Utils::ReplaceString(html, L"<?sell_area?>", SellArea.str(), true);
				}
				else
					html = Utils::ReplaceString(html, L"<?sell_area?>", L"</br>", true);
			}
			else
			{
				html = Utils::ReplaceString(html, L"<?sell_area?>", L"</br>", true);
			}

			pUser->pED->lockAuction.Leave();

			CacheItemsMe(pUser,forceupdate);

			pUser->pED->lockAuction.Enter();
			UINT start_pos2 = 0;
			if( page == 0 ) 
				start_pos2 = 0;
			else if( page > 0 )
				start_pos2 = 11 * page;

			UINT m_UserListSize2 = pUser->pED->m_AuctionItemsMy.size();
			for(UINT m=0; m < 10; m++ )
			{
				UINT pos = m + start_pos2;
				UINT nItemNumber = m + 1;

				if( m + start_pos2 < m_UserListSize2 )
				{
					AuctionItem& ai = pUser->pED->m_AuctionItemsMy[pos];

					wstringstream ItemIconS; ItemIconS << L"<?item_icon" << nItemNumber << L"?>";
					wstringstream ItemIconIm; ItemIconIm << L"<img src=\"" << g_ItemDBEx.GetItemIcon(ai.itemClassId) << L"\" width=32 height=32>";
					html = Utils::ReplaceString(html, ItemIconS.str(), ItemIconIm.str() , true);

					wstringstream wItemInfo;
					if(ai.itemEnchant > 0)
					{
						wItemInfo << L"<font color=LEVEL>+ " << ai.itemEnchant << L"</font>";
					}else
					{
						wItemInfo << L"";
					}
					wItemInfo << L"<a action=\"bypass _auc_can_con?id=" << ai.auctionid << L"\"> " << g_ItemDBEx.GetItemName(ai.itemClassId) << L"</a>";


					if(!wcscmp(g_ItemDBEx.GetItemSA(ai.itemClassId).c_str(), L""))
						wItemInfo << L"";
					else
						wItemInfo << L"<font color=LEVEL> " << g_ItemDBEx.GetItemSA(ai.itemClassId) << L"</font>";

					wstringstream ItemInfo; ItemInfo << L"<?item_in" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemInfo.str(), wItemInfo.str(), true);

					wstringstream ItemGradeS; ItemGradeS << L"<?item_grade" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemGradeS.str(), GetGradeIcon(ai.pInfo->grade), true);

					wstringstream ItemAmountS; ItemAmountS << L"<?item_amount" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemAmountS.str(), Utils::FormatWithCommas(ai.itemAmount), true);

					wstringstream ItemPriceS; ItemPriceS << L"<?item_price" << nItemNumber << L"?>";
					wstringstream ItemPriceFullD; ItemPriceFullD << Utils::FormatWithCommas(ai.itemPrice) << L" " << GetCurrencyHtml(ai.itemPriceID);
					html = Utils::ReplaceString(html, ItemPriceS.str(), ItemPriceFullD.str(), true);
				}
				else
				{
					wstringstream ItemIconS; ItemIconS << L"<?item_icon" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemIconS.str(), L"", true);

					wstringstream ItemEnchantS; ItemEnchantS << L"<?item_enchant" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemEnchantS.str(), L"", true);

					wstringstream ItemAuctionIdS; ItemAuctionIdS << L"<?auction_id" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemAuctionIdS.str(), L"", true);

					wstringstream ItemNameS; ItemNameS << L"<?item_name" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemNameS.str(), L"", true);

					wstringstream ItemSaS; ItemSaS << L"<?item_sa" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemSaS.str(), L"", true);

					wstringstream ItemGradeS; ItemGradeS << L"<?item_grade" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemGradeS.str(), L"", true);

					wstringstream ItemAmountS; ItemAmountS << L"<?item_amount" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemAmountS.str(), L"", true);

					wstringstream ItemPriceS; ItemPriceS << L"<?item_price" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemPriceS.str(), L"", true);

					wstringstream ItemInfo; ItemInfo << L"<?item_in" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemInfo.str(), L"<font color=LEVEL> </font>", true);
				}
			}
			
			html = Utils::ReplaceString(html, L"<?total_auctions?>", m_UserListSize2, true);
			html = Utils::ReplaceString(html, L"<?limit_auctions?>", m_AuctionLimit, true);

			//Count Pages
			UINT m_TotalPages = (m_UserListSize2 / 10);

			UINT next_page2 = 0;
			if( page >= m_TotalPages )
				next_page2 = m_TotalPages;
			else
				next_page2 = page+1;

			html = Utils::ReplaceString(html, L"<?next_page?>", next_page2, true);

			UINT prev_page2 = 0;
			if( page == 0 )
				prev_page2 = 0;
			else
				prev_page2 = page-1;

			html = Utils::ReplaceString(html, L"<?current_page?>", page+1, true);
			html = Utils::ReplaceString(html, L"<?previous_page?>", prev_page2, true);

			html = Utils::ReplaceString(html, L"<?total_pages?>", m_TotalPages+1, true);

			pUser->pED->lockAuction.Leave();

			//g_Log.Add(CLog::Blue, "[%s] size[%d]", __FUNCTION__, html.size());
			pUser->ShowBoard(html.c_str());
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find auction_show.htm !", __FUNCTION__);
		}
	}
	unguard;
	return false;
}

void CAuction::CacheItems(User *pUser, bool forceupdate)
{
	guard;

	if(pUser->pED->m_AuctionExpire < time(0) || forceupdate)
	{
		m_Lock.Enter();
		pUser->pED->lockAuction.Enter();
		pUser->pED->m_AuctionItems.clear();

		UINT m_SearchGrade = pUser->pED->m_AuctionSearchGrade;
		UINT m_SearchCat = pUser->pED->m_AuctionSearchCategory;
		UINT m_SearchSubCat = pUser->pED->m_AuctionSearchSubCategory; //0 = no dialog - 10 = dialog
		wstring wItemName = pUser->pED->wAuctionSearchItemName;

		int n = 0;
		for(map<UINT, AuctionItem>::iterator it = m_Items.begin(); it!= m_Items.end(); it++)
		{
			if( (m_SearchGrade > 0) || (m_SearchCat > 0) || (wcscmp(wItemName.c_str(), L"") ) )
			{
				AuctionItem& ai = it->second;

				bool bGradePass = false;
				bool bCatPass = false;
				bool bSubCatPass = false;
				bool bNamePass = false;
				
				if(m_SearchGrade == 0)
					bGradePass = true;
				else if(m_SearchGrade == 1 && ai.pInfo->grade == CrystalNone)
					bGradePass = true;
				else if(m_SearchGrade == 2 && ai.pInfo->grade == CrystalD)
					bGradePass = true;
				else if(m_SearchGrade == 3 && ai.pInfo->grade == CrystalC)
					bGradePass = true;
				else if(m_SearchGrade == 4 && ai.pInfo->grade == CrystalB)
					bGradePass = true;
				else if(m_SearchGrade == 5 && ai.pInfo->grade == CrystalA)
					bGradePass = true;
				else if(m_SearchGrade == 6 && ai.pInfo->grade == CrystalS)
					bGradePass = true;

				if(m_SearchCat == 0)
				{
					bCatPass = true;
					bSubCatPass = true;
				}
				else if(m_SearchCat == 1) //Accessory
				{
					if((m_SearchSubCat == 0) && ( (ai.pInfo->slot == SlotRightFinger) || (ai.pInfo->slot == SlotRightEar) || (ai.pInfo->slot == SlotNeck) || (ai.pInfo->slot == SlotHair) ) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 1) && (ai.pInfo->slot == SlotRightFinger) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 2) && (ai.pInfo->slot == SlotRightEar) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 3) && (ai.pInfo->slot == SlotNeck) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 4) && (ai.pInfo->slot == SlotHair) )
					{	bSubCatPass = true; bCatPass = true;
					}
				}
				else if(m_SearchCat == 2) //Armor
				{
					if((m_SearchSubCat == 0) && ( (ai.pInfo->slot == SlotHead) || (ai.pInfo->slot == SlotChest) || (ai.pInfo->slot == SlotLegs) || (ai.pInfo->slot == SlotGloves) || (ai.pInfo->slot == SlotFeet) || (ai.pInfo->slot == SlotLeftHand) || (ai.pInfo->slot == SlotBack) ) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 1) && (ai.pInfo->slot == SlotHead) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 2) && (ai.pInfo->slot == SlotChest) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 3) && (ai.pInfo->slot == SlotLegs) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 4) && (ai.pInfo->slot == SlotGloves) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 5) && (ai.pInfo->slot == SlotFeet) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 6) && (ai.pInfo->slot == SlotLeftHand) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 7) && (ai.pInfo->slot == SlotBack) )
					{	bSubCatPass = true; bCatPass = true;
					}

					//Fix for pet armors
					if(ai.pInfo->etcitemtype == EtcItemPetArmor)
						bSubCatPass = false; bCatPass = false;
				}
				else if(m_SearchCat == 3) //Pet Good
				{
					if((m_SearchSubCat == 0) && ( (ai.pInfo->etcitemtype == EtcItemPetCollar) || (ai.pInfo->etcitemtype == EtcItemPetArmor) ) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 1) && (ai.pInfo->etcitemtype == EtcItemPetCollar) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 2) && (ai.pInfo->etcitemtype == EtcItemPetArmor) )
					{	bSubCatPass = true; bCatPass = true;
					}
				}
				else if(m_SearchCat == 4) //Supply
				{
					if((m_SearchSubCat == 0) && ( (ai.pInfo->etcitemtype == EtcItemDye) || (ai.pInfo->etcitemtype == EtcItemScrollEnchantWeapon) || (ai.pInfo->etcitemtype == EtcItemScrollEnchantArmor) || (ai.pInfo->etcitemtype == EtcItemBlessedScrollEnchantWeapon) || (ai.pInfo->etcitemtype == EtcItemBlessedScrollEnchantArmor) || (ai.pInfo->etcitemtype == EtcItemSoulCrystal) || (ai.pInfo->etcitemtype == EtcItemLifeStone) || (ai.pInfo->etcitemtype == EtcItemKeyMaterial) || (ai.pInfo->etcitemtype == EtcItemMaterial) || (ai.pInfo->etcitemtype == EtcItemRecipe) || (ai.pInfo->etcitemtype == EtcItemScroll) || (ai.pInfo->etcitemtype == EtcItemArrow) || (ai.pInfo->etcitemtype == EtcItemPotion) || (ai.pInfo->etcitemtype == EtcItemInfinitySoulshot) || (ai.pInfo->etcitemtype == EtcItemInfinitySpiritshot) || (ai.pInfo->etcitemtype == EtcItemInfinityBlessedSpiritshot) || (ai.pInfo->etcitemtype == EtcItemSpellbook)   ) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 1) && (ai.pInfo->etcitemtype == EtcItemDye) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 2) && ( (ai.pInfo->etcitemtype == EtcItemScrollEnchantWeapon) || (ai.pInfo->etcitemtype == EtcItemScrollEnchantArmor) || (ai.pInfo->etcitemtype == EtcItemBlessedScrollEnchantWeapon) || (ai.pInfo->etcitemtype == EtcItemBlessedScrollEnchantArmor) ) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 3) && (ai.pInfo->etcitemtype == EtcItemSoulCrystal) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 4) && (ai.pInfo->etcitemtype == EtcItemLifeStone) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 5) && (ai.pInfo->etcitemtype == EtcItemKeyMaterial) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 6) && (ai.pInfo->etcitemtype == EtcItemMaterial) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 7) && (ai.pInfo->etcitemtype == EtcItemRecipe) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 8) && ( (ai.pInfo->etcitemtype == EtcItemScroll) || (ai.pInfo->etcitemtype == EtcItemArrow) || (ai.pInfo->etcitemtype == EtcItemPotion) || (ai.pInfo->etcitemtype == EtcItemInfinitySoulshot) || (ai.pInfo->etcitemtype == EtcItemInfinitySpiritshot) || (ai.pInfo->etcitemtype == EtcItemInfinityBlessedSpiritshot) ) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 9) && (ai.pInfo->etcitemtype == EtcItemSpellbook) )
					{	bSubCatPass = true; bCatPass = true;
					}
				}
				else if(m_SearchCat == 5) //Weapon
				{
					if((m_SearchSubCat == 0) && ( (ai.pInfo->weapontype == WeaponSword) || (ai.pInfo->weapontype == WeaponBlunt) || (ai.pInfo->weapontype == WeaponDagger) || (ai.pInfo->weapontype == WeaponBow) || (ai.pInfo->weapontype == WeaponPole) || (ai.pInfo->weapontype == WeaponFist) || (ai.pInfo->weapontype == WeaponEtc) || (ai.pInfo->weapontype == WeaponDual)  ) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 1) && (ai.pInfo->weapontype == WeaponSword) && (ai.pInfo->slot == SlotRightHand) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 2) && (ai.pInfo->weapontype == WeaponSword) && (ai.pInfo->slot == SlotRightLeftHand) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 3) && (ai.pInfo->weapontype == WeaponBlunt) && (ai.pInfo->slot == SlotRightHand) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 4) && (ai.pInfo->weapontype == WeaponBlunt) && (ai.pInfo->slot == SlotRightLeftHand) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 5) && (ai.pInfo->weapontype == WeaponDagger) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 6) && (ai.pInfo->weapontype == WeaponBow) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 7) && (ai.pInfo->weapontype == WeaponPole) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 8) && (ai.pInfo->weapontype == WeaponFist) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 9) && (ai.pInfo->weapontype == WeaponEtc) )
					{	bSubCatPass = true; bCatPass = true;
					}else if((m_SearchSubCat == 10) && (ai.pInfo->weapontype == WeaponDual) )
					{	bSubCatPass = true; bCatPass = true;
					}
				}

				wstring wItemNameClient = ai.pInfo->clientname;
				transform(wItemName.begin(), wItemName.end(), wItemName.begin(), tolower);
				transform(wItemNameClient.begin(), wItemNameClient.end(), wItemNameClient.begin(), tolower);


				if( !wcscmp(wItemName.c_str(), L"") )
					bNamePass = true;
				
				int nResultName = wItemNameClient.find(wItemName);
				if(nResultName == 0)
					nResultName = 1;

				if(nResultName == -1)
					nResultName = 0;

				if( nResultName > 0 )
					bNamePass = true;

				//g_Log.Add(CLog::Error, "[%s] [%d][%d][%d][%d][%d][%S][%S]", __FUNCTION__, bGradePass , bCatPass , bSubCatPass , bNamePass, wItemNameClient.find(wItemName.c_str()), wItemNameClient.c_str(), wItemName.c_str());

				if(bGradePass && bCatPass && bSubCatPass && bNamePass)
				{
					pUser->pED->m_AuctionItems.insert(pair<UINT, AuctionItem>(n, it->second));
					n++;
				}
			}
			else
			{
				pUser->pED->m_AuctionItems.insert(pair<UINT, AuctionItem>(n, it->second));
				n++;
			}
		}
		pUser->pED->m_AuctionExpire = time(0) + 120;
		pUser->pED->lockAuction.Leave();
		m_Lock.Leave();
	}

	unguard;
}

bool CAuction::RequestShowAuction(User *pUser, UINT page, bool forceupdate)
{
	guard;
	if(m_Enabled && pUser->ValidUser())
	{
		const WCHAR *wHtml = g_HtmlCache.Get(L"auction_show.htm");
		if(wHtml)
		{
			wstring html(wHtml);
		
			CacheItems(pUser, forceupdate);

			UINT start_pos = 0;
			if( page == 0 ) 
				start_pos = 0;
			else if( page > 0 )
				start_pos = 11 * page;

			pUser->pED->lockAuction.Enter();

			UINT m_UserListSize = pUser->pED->m_AuctionItems.size();
			for(UINT m=0; m < 11; m++ )
			{
				UINT pos = m + start_pos;
				UINT nItemNumber = m + 1;

				if( m + start_pos < m_UserListSize )
				{
					AuctionItem& ai = pUser->pED->m_AuctionItems[pos];

					wstringstream ItemIconS; ItemIconS << L"<?item_icon" << nItemNumber << L"?>";
					wstringstream ItemIconIm; ItemIconIm << L"<img src=\"" << g_ItemDBEx.GetItemIcon(ai.itemClassId) << L"\" width=32 height=32>";
					html = Utils::ReplaceString(html, ItemIconS.str(), ItemIconIm.str() , true);

					wstringstream ItemEnchantS; ItemEnchantS << L"<?item_enchant" << nItemNumber << L"?>";
					if(ai.itemEnchant > 0)
					{
						wstringstream enchantStream; enchantStream << L"+" << ai.itemEnchant;
						html = Utils::ReplaceString(html, ItemEnchantS.str(), enchantStream.str(), true);
					}else
					{
						html = Utils::ReplaceString(html, ItemEnchantS.str(), L"", true);
					}

					wstringstream ItemAuctionIdS; ItemAuctionIdS << L"<?auction_id" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemAuctionIdS.str(), ai.auctionid, true);

					wstringstream ItemNameS; ItemNameS << L"<?item_name" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemNameS.str(), g_ItemDBEx.GetItemName(ai.itemClassId), true);

					wstringstream ItemSaS; ItemSaS << L"<?item_sa" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemSaS.str(), g_ItemDBEx.GetItemSA(ai.itemClassId), true);

					wstringstream ItemGradeS; ItemGradeS << L"<?item_grade" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemGradeS.str(), GetGradeIcon(ai.pInfo->grade), true);

					wstringstream ItemAmountS; ItemAmountS << L"<?item_amount" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemAmountS.str(), Utils::FormatWithCommas(ai.itemAmount), true);

					
					wstringstream ItemPriceS; ItemPriceS << L"<?item_price" << nItemNumber << L"?>";
					wstringstream ItemPriceFullD; ItemPriceFullD << Utils::FormatWithCommas(ai.itemPrice) << L" " << GetCurrencyHtml(ai.itemPriceID);
					html = Utils::ReplaceString(html, ItemPriceS.str(), ItemPriceFullD.str(), true);
				}
				else
				{
					wstringstream ItemIconS; ItemIconS << L"<?item_icon" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemIconS.str(), L"", true);

					wstringstream ItemEnchantS; ItemEnchantS << L"<?item_enchant" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemEnchantS.str(), L"", true);

					wstringstream ItemAuctionIdS; ItemAuctionIdS << L"<?auction_id" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemAuctionIdS.str(), L"", true);

					wstringstream ItemNameS; ItemNameS << L"<?item_name" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemNameS.str(), L"", true);

					wstringstream ItemSaS; ItemSaS << L"<?item_sa" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemSaS.str(), L"", true);

					wstringstream ItemGradeS; ItemGradeS << L"<?item_grade" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemGradeS.str(), L"", true);

					wstringstream ItemAmountS; ItemAmountS << L"<?item_amount" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemAmountS.str(), L"", true);

					wstringstream ItemPriceS; ItemPriceS << L"<?item_price" << nItemNumber << L"?>";
					html = Utils::ReplaceString(html, ItemPriceS.str(), L"", true);
				}
			}
			pUser->pED->lockAuction.Leave();

			//Count Pages
			UINT m_TotalPages = (m_UserListSize / 11);

			UINT next_page = 0;
			if( page >= m_TotalPages )
				next_page = m_TotalPages;
			else
				next_page = page+1;

			html = Utils::ReplaceString(html, L"<?next_page?>", next_page, true);

			UINT prev_page = 0;
			if( page == 0 )
				prev_page = 0;
			else
				prev_page = page-1;

			html = Utils::ReplaceString(html, L"<?current_page?>", page+1, true);
			html = Utils::ReplaceString(html, L"<?previous_page?>", prev_page, true);

			html = Utils::ReplaceString(html, L"<?total_pages?>", m_TotalPages+1, true);

			html = Utils::ReplaceString(html, L"<?panel?>", ShowSearchPanel(pUser), true);
			

			//g_Log.Add(CLog::Blue, "[%s] size[%d]", __FUNCTION__, html.size());
			pUser->ShowBoard(html.c_str());
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find auction_show.htm !", __FUNCTION__);
		}
	}
	unguard;
	return false;
}

bool CAuction::RequestSetAuctionConfirm(User *pUser, UINT itemDbId, wstring pricename, int price, int amount)
{
	guard;
	if(m_Enabled && pUser->ValidUser())
	{
		if(CItem *pItem = pUser->inventory.GetItemByDBID(itemDbId))
		{
			//check if pItem exist?
			const WCHAR *wHtml = g_HtmlCache.Get(L"auction_set_confirm.htm");
			if(wHtml)
			{
				wstring html(wHtml);

				html = Utils::ReplaceString(html, L"<?item_name?>", g_ItemDBEx.GetItemName(pItem->pSID->nItemID), true);
				html = Utils::ReplaceString(html, L"<?item_icon?>", g_ItemDBEx.GetItemIcon(pItem->pSID->nItemID), true);
				if(pItem->pSID->nEnchantLevel > 0)
				{
					wstringstream enchantStream;
					enchantStream << L"+" << pItem->pSID->nEnchantLevel;
					html = Utils::ReplaceString(html, L"<?item_enchant?>", enchantStream.str(), true);
				}else
				{
					html = Utils::ReplaceString(html, L"<?item_enchant?>", L"", true);
				}
				

				CItemInformation *pInfo = NULL;
				m_Lock.Enter();
				for(UINT n=0;n<pUser->pED->m_ItemAuctionList.size();n++)
				{
					if(pUser->pED->m_ItemAuctionList[n].itemDBId == itemDbId)
					{
						pInfo = pUser->pED->m_ItemAuctionList[n].pInfo;
					}
				}
				m_Lock.Leave();

				//Get Desc

				html = Utils::ReplaceString(html, L"<?description?>", GetItemDesc(pInfo, pItem->pSID->nEnchantLevel, pItem->nAugmentationID), true);

				html = Utils::ReplaceString(html, L"<?grade_icon?>", GetGradeIcon(pItem->pII->nCrystalType), true);

				html = Utils::ReplaceString(html, L"<?item_id?>", itemDbId, true);

				UINT nCurrencyId = GetCurrencyId(pricename);
				wstring m_CurrencyName = GetCurrencyName(nCurrencyId);

				html = Utils::ReplaceString(html, L"<?price_name?>", m_CurrencyName, true);
				html = Utils::ReplaceString(html, L"<?priceid?>", nCurrencyId, true);

				html = Utils::ReplaceString(html, L"<?price_per_item?>", Utils::FormatWithCommas(price), true);
				html = Utils::ReplaceString(html, L"<?price_per_item2?>", price, true);

				html = Utils::ReplaceString(html, L"<?amount?>", Utils::FormatWithCommas(amount), true);
				html = Utils::ReplaceString(html, L"<?amount2?>", amount, true);

				pUser->ShowBoard(html.c_str());
			}
		}
		else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find item[%d] in inventory[%S]", __FUNCTION__, itemDbId, pUser->pSD->wszName);
		}
	}
	unguard;
	return false;
}

bool CAuction::RequestSetAuction(User *pUser, UINT itemid, UINT priceId, int price, int amount)
{
	guard;
	if(m_Enabled && pUser->ValidUser())
	{
		if(m_PeaceMode && !pUser->inPeaceZone)
		{
			//2662	1	You can use auction house only into Peace Mode! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2662);
			pUser->HideBoard();
			unguard;
			return false;
		}

		if(m_KarmaDisable && pUser->pSD->nKarma)
		{
			//2663	1	You can use auction house only if you don't have Karma! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2663);
			pUser->HideBoard();
			unguard;
			return false;
		}

		if(pUser->pSD->bGuilty || pUser->IsInCombatMode())
		{
			//2664	1	You cannot use auction house during combat mode! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2664);
			pUser->HideBoard();
			unguard;
			return false;
		}
		if( pUser->olympiadUser.IsInside() || pUser->pED->tvtUser.status == TvT::UserFighting )
		{
			//2664	1	You cannot use auction house during combat mode! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2664);
			pUser->HideBoard();
			unguard;
			return false;
		}

		if(CItem *pItem = pUser->inventory.GetItemByDBID(itemid))
		{
			if(amount > 0 && amount <= pItem->pSID->nItemAmount)
			{
				if(price > 0 && price < INT_MAX)
				{
					INT64 totalPrice = price * amount;
					if(totalPrice < INT_MAX)
					{
						if( pUser->pED->m_TotalAuctions < m_AuctionLimit)
						{
							bool pricefound = false;
							map<UINT, SellCurrency>::iterator Iter = m_SellCurrency.find(priceId);
							if(Iter!=m_SellCurrency.end())
							{
								pricefound = true;
							}

							if(pricefound)
							{
								if(m_AuctionFee > 0)
								{
									if(!pUser->inventory.HaveItemByClassID(m_AuctionFeeID, m_AuctionFee))
									{
										//pUser->SendSystemMessage(L"You don't have enough adena to pay auction fee.");
										//2665	1	You don't have enough adena to pay auction fee. 	0	79	9B	B0	FF			0	0	0	0	0		none
										pUser->pSocket->SendSystemMessage(2665);
										RequestShowAuctionMe(pUser,0,0,0);
										unguard;
										return false;
									}
									if(pUser->IsNowTrade())
										pUser->TradeCancel();

									if(m_AuctionFeeDel)
										pUser->DeleteItemInInventory(m_AuctionFeeID, m_AuctionFee);
								}

								g_DB.RequestDestroyItem(pItem, amount, pUser); //wtf? why like this?
								time_t nExpireTime = time(0);
								if(m_AuctionTime) { nExpireTime = (time(0) + m_AuctionTime); } else { nExpireTime = 0; }
								g_DB.RequestCreateAuction(pUser->nDBID, pUser->pSD->wszName, pItem->pSID->nItemID, amount, pItem->pSID->nEnchantLevel, pItem->nAugmentationID, priceId, price, nExpireTime); //for price check
								g_Logger.Add(L"User[%s] - request create auction item[%d] amount[%d] enchant[%d] augmentation[%d] price[%d]", pUser->pSD->wszName, pItem->pSID->nItemID, amount, pItem->pSID->nEnchantLevel, pItem->nAugmentationID, price);
								
								//RequestShowAuctionMe(pUser,L"",0,0,0,true);
								unguard;
								return true;
							}else
							{
								pUser->SendSystemMessage(L"Something gone wrong! Please try again!");
								RequestShowAuctionMe(pUser,0,0,0);
							}
						}else
						{
							//pUser->SendSystemMessage(L"You cannot set more auctions! You reached the limit!");
							//2666	1	You cannot set more auctions! You reached the limit! 	0	79	9B	B0	FF			0	0	0	0	0		none
							pUser->pSocket->SendSystemMessage(2666);
							RequestShowAuctionMe(pUser,0,0,0);
						}

					}else
					{
						//348	1	a,Incorrect item price.\0	5	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,error\0
						pUser->pSocket->SendSystemMessage(348);
						RequestShowAuctionMe(pUser,0,0,0);
					}
				}else
				{
					//348	1	a,Incorrect item price.\0	5	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,error\0
					pUser->pSocket->SendSystemMessage(348);
					RequestShowAuctionMe(pUser,0,0,0);
				}
			}else
			{
				//347	1	a,Incorrect item count.\0	5	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,error\0
				pUser->pSocket->SendSystemMessage(347);
				RequestShowAuctionMe(pUser,0,0,0);

			}
		}else
		{
			RequestShowAuctionMe(pUser,0,0,0,true);
			g_Log.Add(CLog::Error, "[%s] Cannot find item[%d] in inventory[%S]", __FUNCTION__, itemid, pUser->pSD->wszName);
		}
	}
	unguard;
	return false;
};

bool CAuction::Create(UINT sellerId, const WCHAR *sellerName, UINT auctionId, INT32 itemId, INT32 amount, INT32 enchant, UINT augmentation, INT32 priceId, INT32 price, UINT expireTime, bool loadOnly)
{
	guard;

	if(m_Enabled)
	{
		AuctionItem ai;
		ai.auctionTimeoutTime = expireTime;
		ai.itemAmount = amount;
		//ai.itemAugmentation = Augmentation(augmentation);
		ai.itemAugmentation = augmentation;
		ai.itemClassId = itemId;
		ai.itemEnchant = enchant;
		ai.itemPrice = price;
		ai.itemPriceID = priceId;
		ai.sellerDatabaseId = sellerId;
		wcscpy_s(ai.sellerName, 25, sellerName);
		ai.pInfo = g_ItemDBEx.GetItemInfo(itemId);
		ai.auctionid = auctionId;

		m_Lock.Enter();
		m_Items.insert(pair<UINT, AuctionItem>(auctionId, ai));
		m_Lock.Leave();

		if(!loadOnly)
		{
			if(User *pUser = g_UserDB.GetUserByDBID(sellerId))
			{
				//pUser->SendSystemMessage(L"The auction has been created.");
				//2667	1	Your auction has been created! 	0	79	9B	B0	FF			0	0	0	0	0		none
				pUser->pSocket->SendSystemMessage(2667);
				RequestShowAuctionMe(pUser, 0, 0, 0,true);
			}
		}
	}


	unguard;
	return false;
}

bool CAuction::Delete(UINT auctionId)
{
	guard;

	if(m_Enabled)
	{
		m_Lock.Enter();
		map<UINT, AuctionItem>::iterator Iter = m_Items.find(auctionId);
		if(Iter!=m_Items.end())
		{
			m_Items.erase(Iter);
		}
		else
		{
			m_Lock.Leave();
			unguard;
			return false;
		}
		m_Lock.Leave();

		g_DB.RequestDeleteAuction(auctionId);

		unguard;
		return true;
	}

	unguard;
	return false;
}

bool CAuction::RequestCancelAuctionConfirm(User *pUser, UINT nAuctionId)
{
	guard;
	if(m_Enabled && pUser->ValidUser())
	{
		AuctionItem ai;
		memset(&ai, 0, sizeof(AuctionItem));
		m_Lock.Enter();
		map<UINT, AuctionItem>::iterator Iter = m_Items.find(nAuctionId);
		if(Iter!=m_Items.end())
		{
			ai = Iter->second;
		}
		m_Lock.Leave();

		if(ai.sellerDatabaseId == pUser->pSD->nDBID)
		{
			const WCHAR *wHtml = g_HtmlCache.Get(L"auction_cancel_confirm.htm");
			if(wHtml)
			{
				CItemInformation *pInfo = ai.pInfo;
				wstring html(wHtml);

				html = Utils::ReplaceString(html, L"<?item_name?>", g_ItemDBEx.GetItemName(ai.itemClassId), true);
				html = Utils::ReplaceString(html, L"<?item_icon?>", g_ItemDBEx.GetItemIcon(ai.itemClassId), true);
				if(ai.itemEnchant > 0)
				{
					wstringstream enchantStream;
					enchantStream << L"+" << ai.itemEnchant;
					html = Utils::ReplaceString(html, L"<?item_enchant?>", enchantStream.str(), true);
				}else
				{
					html = Utils::ReplaceString(html, L"<?item_enchant?>", L"", true);
				}			
				html = Utils::ReplaceString(html, L"<?description?>", GetItemDesc(pInfo, ai.itemEnchant, ai.itemAugmentation), true);

				html = Utils::ReplaceString(html, L"<?grade_icon?>", GetGradeIcon(pInfo->grade), true);

				html = Utils::ReplaceString(html, L"<?auction_id?>", nAuctionId, true);
				html = Utils::ReplaceString(html, L"<?price_name?>", g_ItemDBEx.GetItemName(ai.itemPriceID), true);
				html = Utils::ReplaceString(html, L"<?price_per_item?>", Utils::FormatWithCommas(ai.itemPrice), true);
				html = Utils::ReplaceString(html, L"<?amount?>", ai.itemAmount, true);

				pUser->ShowBoard(html.c_str());
			}
		}
		else
		{
			pUser->SendSystemMessage(L"Your auction cannot be found, please try again!");
			RequestShowAuctionMe(pUser, 0, 0, 0);
			g_Log.Add(CLog::Error, "[%s] Cannot find Auction ID[%d] in Auction List!", __FUNCTION__, nAuctionId);
		}
	}
	unguard;
	return false;
}


bool CAuction::RequestCancelAuction(User *pUser, UINT auctionId)
{
	guard;

	if(m_Enabled && pUser->ValidUser())
	{
		if(m_PeaceMode && !pUser->inPeaceZone)
		{
			//2662	1	You can use auction house only into Peace Mode! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2662);
			pUser->HideBoard();
			unguard;
			return false;
		}

		if(m_KarmaDisable && pUser->pSD->nKarma)
		{
			//2663	1	You can use auction house only if you don't have Karma! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2663);
			pUser->HideBoard();
			unguard;
			return false;
		}

		if(pUser->pSD->bGuilty || pUser->IsInCombatMode())
		{
			//2664	1	You cannot use auction house during combat mode! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2664);
			pUser->HideBoard();
			unguard;
			return false;
		}
		if( pUser->olympiadUser.IsInside() || pUser->pED->tvtUser.status == TvT::UserFighting )
		{
			//2664	1	You cannot use auction house during combat mode! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2664);
			pUser->HideBoard();
			unguard;
			return false;
		}

		//check if auctionid is on this user
		bool found = true;
		m_Lock.Enter();
		AuctionItem ai;
		memset(&ai, 0, sizeof(AuctionItem));
		map<UINT, AuctionItem>::iterator Iter = m_Items.find(auctionId);
		if(Iter!=m_Items.end())
		{
			ai = Iter->second;
		}
		else
		{
			found = false;
		}
		m_Lock.Leave();

		if(found)
		{
			if(pUser->nDBID == ai.sellerDatabaseId)
			{
				if(pUser->inventory.CheckAddable(ai.itemClassId, ai.itemAmount) && pUser->IsNowTrade() == false && pUser->pSD->nStoreMode == 0)
				{
					if(Delete(auctionId))
					{
							pUser->AddItemToInventory(ai.itemClassId, ai.itemAmount, false, ai.itemEnchant, 0, 0, ai.itemAugmentation);

							//show againmyauctionboard
							RequestShowAuctionMe(pUser, 0, 0, 0, true);

							//send the user message
							//pUser->SendSystemMessageGreen(L"You successfully deleted your auction!");
							//2668	1	You successfully removed your auction! 	0	79	9B	B0	FF			0	0	0	0	0		none
							pUser->pSocket->SendSystemMessage(2668);

							g_Logger.Add(L"Auction: User[%s] Deleted Auction ID[%d] ItemID[%d] Amount[%d] Enchant[%d] Augmentation[%d]", pUser->pSD->wszName, auctionId, ai.itemClassId, ai.itemAmount, ai.itemEnchant, ai.itemAugmentation);
					}
					else
					{
						//pUser->SendSystemMessage(L"Your auction cannot be found, please try again!");
						//2669	1	Your auction cannot be found, please try again! 	0	79	9B	B0	FF			0	0	0	0	0		none
						pUser->pSocket->SendSystemMessage(2669);
						RequestShowAuctionMe(pUser, 0, 0, 0, false);
					}
				}
				else
				{
					//pUser->SendSystemMessage(L"You don't have enough space in your inventory in order to delete your auction!!!");
					//2670	1	You don't have enough space in your inventory in order to delete your auction! 	0	79	9B	B0	FF			0	0	0	0	0		none
					pUser->pSocket->SendSystemMessage(2670);
					RequestShowAuctionMe(pUser, 0, 0, 0, false);
				}
			}
			else
			{
				//pUser->SendSystemMessage(L"Something gone wrong with the cancellation of the auction. Please Try Again!");
				//2671	1	Something gone wrong with the cancellation of the auction. Please Try Again! 	0	79	9B	B0	FF			0	0	0	0	0		none
				pUser->pSocket->SendSystemMessage(2671);
				RequestShowAuctionMe(pUser, 0, 0, 0, false);
			}
		}
		else
		{
			//pUser->SendSystemMessage(L"We cannot locate your auction, propably it sold!");
			//2672	1	We cannot locate your auction, propably it sold! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2672);
			RequestShowAuctionMe(pUser, 0, 0, 0, true);
		}
	}

	unguard;
	return false;
}

bool CAuction::RequestBuyAuctionPreview(User *pUser, UINT nAuctionId)
{
	guard;
	if(m_Enabled && pUser->ValidUser())
	{
		bool found = false;
		AuctionItem ai;
		memset(&ai, 0, sizeof(AuctionItem));
		m_Lock.Enter();
		map<UINT, AuctionItem>::iterator Iter = m_Items.find(nAuctionId);
		if(Iter!=m_Items.end())
		{
			ai = Iter->second;
			found = true;
		}
		m_Lock.Leave();

		if(found)
		{
			const WCHAR *wHtml = g_HtmlCache.Get(L"auction_buy_preview.htm");
			if(wHtml)
			{
				CItemInformation *pInfo = ai.pInfo;
				wstring html(wHtml);

				html = Utils::ReplaceString(html, L"<?item_name?>", g_ItemDBEx.GetItemName(ai.itemClassId), true);
				html = Utils::ReplaceString(html, L"<?item_icon?>", g_ItemDBEx.GetItemIcon(ai.itemClassId), true);
				if(ai.itemEnchant > 0)
				{
					wstringstream enchantStream;
					enchantStream << L"+" << ai.itemEnchant;
					html = Utils::ReplaceString(html, L"<?item_enchant?>", enchantStream.str(), true);
				}else
				{
					html = Utils::ReplaceString(html, L"<?item_enchant?>", L"", true);
				}			
				html = Utils::ReplaceString(html, L"<?description?>", GetItemDesc(pInfo, ai.itemEnchant, ai.itemAugmentation), true);
				html = Utils::ReplaceString(html, L"<?grade_icon?>", GetGradeIcon(pInfo->grade), true);

				if(ai.itemAmount > 1)
				{
					html = Utils::ReplaceString(html, L"<?amount_input?>", L"<edit type=\"number\" var=\"amount\" height=10 width=100>", true);
					html = Utils::ReplaceString(html, L"<?amount_send?>", L"amount= $amount ", true);
				}
				else
				{
					html = Utils::ReplaceString(html, L"<?amount_input?>", L"1", true);
					html = Utils::ReplaceString(html, L"<?amount_send?>", L"amount=1", true);
				}

				html = Utils::ReplaceString(html, L"<?auction_id?>", nAuctionId, true);
				html = Utils::ReplaceString(html, L"<?price_name?>", g_ItemDBEx.GetItemName(ai.itemPriceID), true);
				html = Utils::ReplaceString(html, L"<?price_per_item?>", Utils::FormatWithCommas(ai.itemPrice), true);
				html = Utils::ReplaceString(html, L"<?amount?>", ai.itemAmount, true);

				pUser->ShowBoard(html.c_str());
			}
		}
		else
		{
			pUser->SendSystemMessage(L"This auction cannot be found, please try again!");
			RequestShowAuction(pUser, 0, true);
			g_Log.Add(CLog::Error, "[%s] Cannot find Auction ID[%d] in Auction List!", __FUNCTION__, nAuctionId);
		}
	}
	unguard;
	return false;
}

bool CAuction::RequestBuyAuctionConfirm(User *pUser, UINT nAuctionId, UINT nItemAmount)
{
	guard;
	if(m_Enabled && pUser->ValidUser())
	{
		bool found = false;
		AuctionItem ai;
		memset(&ai, 0, sizeof(AuctionItem));
		m_Lock.Enter();
		map<UINT, AuctionItem>::iterator Iter = m_Items.find(nAuctionId);
		if(Iter!=m_Items.end())
		{
			ai = Iter->second;
			found = true;
		}
		m_Lock.Leave();

		if(found)
		{
			if( (nItemAmount != 0) && (nItemAmount <= (UINT)ai.itemAmount) ) //if( (nItemAmount != 0) && (nItemAmount <= (UINT)ai.itemAmount) )
			{
				const WCHAR *wHtml = g_HtmlCache.Get(L"auction_buy_confirm.htm");
				if(wHtml)
				{
					CItemInformation *pInfo = ai.pInfo;
					wstring html(wHtml);

					html = Utils::ReplaceString(html, L"<?item_name?>", g_ItemDBEx.GetItemName(ai.itemClassId), true);
					html = Utils::ReplaceString(html, L"<?item_icon?>", g_ItemDBEx.GetItemIcon(ai.itemClassId), true);
					if(ai.itemEnchant > 0)
					{
						wstringstream enchantStream;
						enchantStream << L"+" << ai.itemEnchant;
						html = Utils::ReplaceString(html, L"<?item_enchant?>", enchantStream.str(), true);
					}else
					{
						html = Utils::ReplaceString(html, L"<?item_enchant?>", L"", true);
					}			
					html = Utils::ReplaceString(html, L"<?description?>", GetItemDesc(pInfo, ai.itemEnchant, ai.itemAugmentation), true);
					html = Utils::ReplaceString(html, L"<?grade_icon?>", GetGradeIcon(pInfo->grade), true);

					html = Utils::ReplaceString(html, L"<?amount_input?>", nItemAmount, true);
					html = Utils::ReplaceString(html, L"<?auction_id?>", nAuctionId, true);
					html = Utils::ReplaceString(html, L"<?price_name?>", g_ItemDBEx.GetItemName(ai.itemPriceID), true);
					html = Utils::ReplaceString(html, L"<?price_per_item?>", Utils::FormatWithCommas(ai.itemPrice), true);
					
					UINT total_price = nItemAmount * ai.itemPrice;
					html = Utils::ReplaceString(html, L"<?total_price?>", total_price, true);
					html = Utils::ReplaceString(html, L"<?amount?>", ai.itemAmount, true);

					pUser->ShowBoard(html.c_str());
				}
			}
			else
			{
				//pUser->SendSystemMessage(L"The item ammount which you entered is wrong!");
				//348	1	a,Incorrect item price.\0	5	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,error\0
				pUser->pSocket->SendSystemMessage(348);
				RequestBuyAuctionPreview(pUser, nAuctionId);
				g_Log.Add(CLog::Error, "[%s] User[%s] sended wrong ammount on Auction ID[%d], Requested Amount[%d], Auction Amount[%d]!", __FUNCTION__, pUser->pSD->wszName ,nAuctionId, nItemAmount, ai.itemAmount );
			}
		}
		else
		{
			//pUser->SendSystemMessage(L"This auction cannot be found, please try again!");
			//2669	1	Your auction cannot be found, please try again! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2669);

			RequestShowAuction(pUser, 0);
			g_Log.Add(CLog::Error, "[%s] Cannot find Auction ID[%d] in Auction List!", __FUNCTION__, nAuctionId);
		}
	}
	unguard;
	return false;
}

bool CAuction::RequestBuy(User *pUser, UINT auctionId, INT32 amount)
{
	guard;
	if(m_Enabled && pUser->ValidUser())
	{
		if(m_PeaceMode && !pUser->inPeaceZone)
		{
			//2662	1	You can use auction house only into Peace Mode! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2662);
			pUser->HideBoard();
			unguard;
			return false;
		}

		if(m_KarmaDisable && pUser->pSD->nKarma)
		{
			//2663	1	You can use auction house only if you don't have Karma! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2663);
			pUser->HideBoard();
			unguard;
			return false;
		}

		if(pUser->pSD->bGuilty || pUser->IsInCombatMode())
		{
			//2664	1	You cannot use auction house during combat mode! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2664);
			pUser->HideBoard();
			unguard;
			return false;
		}
		if( pUser->olympiadUser.IsInside() || pUser->pED->tvtUser.status == TvT::UserFighting )
		{
			//2664	1	You cannot use auction house during combat mode! 	0	79	9B	B0	FF			0	0	0	0	0		none
			pUser->pSocket->SendSystemMessage(2664);
			pUser->HideBoard();
			unguard;
			return false;
		}

		if(auctionId > 0)
		{
			if(amount > 0)
			{
				AuctionItem ai;
				memset(&ai, 0, sizeof(AuctionItem));

				bool updateAmount = false;
				bool noAuction = false;
				bool notEnoughAdena = false;
				bool notEnoughSpaceInInventory = false;
				bool notEnoughItemsLeft = false;
				bool myitem = false;
				INT64 totalPrice = 0;
				m_Lock.Enter();
				map<UINT, AuctionItem>::iterator it = m_Items.find(auctionId);
				if(it != m_Items.end())
				{
					memcpy(&ai, &it->second, sizeof(AuctionItem));
					if((ai.auctionTimeoutTime > time(0)) || (ai.auctionTimeoutTime == 0) )
					{
						if(ai.sellerDatabaseId != pUser->nDBID)
						{
							if(pUser->inventory.CheckAddable(ai.itemClassId, amount))
							{
								totalPrice = ai.itemPrice * amount;
								//CItem *pItem = pUser->inventory.GetFirstItemByClassID(ai.itemPriceID);
								//if(totalPrice <= pUser->inventory.GetAdenaAmount()) //for price id check
								if(pUser->inventory.HaveItemByClassID(ai.itemPriceID, totalPrice))
								{
									if(amount <= ai.itemAmount)
									{
										updateAmount = true;
										ai.itemAmount -= amount;
										it->second.itemAmount = ai.itemAmount;
										if(ai.itemAmount == 0)
										{
											m_Items.erase(it);
										}
									}else
									{
										notEnoughItemsLeft = true;
									}
								}else
								{
									notEnoughAdena = true;
								}
							}else
							{
								notEnoughSpaceInInventory = true;
							}
						}else
						{
							myitem = true;
						}
					}else
					{
						noAuction = true;
					}
				}else
				{
					noAuction = true;
				}
				m_Lock.Leave();

				if(noAuction)
				{
					//pUser->SendSystemMessage(L"The auction doesn't exist anymore.");
					//2673	1	The auction doesn't exist anymore! 	0	79	9B	B0	FF			0	0	0	0	0		none
					pUser->pSocket->SendSystemMessage(2673);

					RequestShowAuction(pUser, 0, true);
					unguard;
					return false;
				}
				if(notEnoughItemsLeft)
				{
					//pUser->SendSystemMessage(L"We're sorry there are not enough items left in the auction.");
					//2674	1	We're sorry there are not enough items left in the auction! 	0	79	9B	B0	FF			0	0	0	0	0		none
					pUser->pSocket->SendSystemMessage(2674);
					RequestShowAuction(pUser, 0);
					unguard;
					return false;
				}
				if(notEnoughAdena)
				{
					//pUser->SendSystemMessage(L"You dont have the required items in order to buy this item.");
					//2675	1	You dont have the required items in order to buy this item! 	0	79	9B	B0	FF			0	0	0	0	0		none
					pUser->pSocket->SendSystemMessage(2675);
					RequestShowAuction(pUser, 0);
					unguard;
					return false;
				}
				if(notEnoughSpaceInInventory)
				{
					//pUser->SendSystemMessage(L"You've got not enough space in your inventory.");
					//2676	1	You've got not enough space in your inventory! 	0	79	9B	B0	FF			0	0	0	0	0		none
					pUser->pSocket->SendSystemMessage(2676);
					RequestShowAuction(pUser, 0);
					unguard;
					return false;
				}
				if(myitem)
				{
					//pUser->SendSystemMessage(L"You cannot buy your own item!");
					//2677	1	You cannot buy your own item! 	0	79	9B	B0	FF			0	0	0	0	0		none
					pUser->pSocket->SendSystemMessage(2677);
					RequestShowAuction(pUser, 0);
					unguard;
					return false;
				}

				if(updateAmount)
				{
					if(pUser->IsNowTrade())
						pUser->TradeCancel();

					pUser->DeleteItemInInventory(ai.itemPriceID, totalPrice); //for price check					
					pUser->AddItemToInventory(ai.itemClassId, amount, false, ai.itemEnchant, 0, 0, ai.itemAugmentation);

					g_Logger.Add(L"User[%s] bought auction[%d] seller[%s][%d] item[%d] amount[%d]", pUser->pSD->wszName, auctionId, ai.sellerName, ai.sellerDatabaseId, ai.itemClassId, amount);
					if(ai.itemAmount > 0)
					{
						g_DB.RequestModdifyAuctionAmount(auctionId, ai.itemAmount);
					}else
					{
						g_DB.RequestDeleteAuction(auctionId);
					}

					g_DB.RequestAuctionAddPaymentJob(ai.sellerDatabaseId, ai.itemPriceID, totalPrice, ai.itemClassId, amount, pUser->pSD->wszName); //for price check

					//Message That buy was successfull
					wstringstream msg;
					msg << L"You've just bought " << amount << L" " << g_ItemDBEx.GetItemName(ai.itemClassId) << L" for " << totalPrice << L" " << g_ItemDBEx.GetItemName(ai.itemPriceID) << L" through Auction House.";

					//TODO
					//2678	1	You've just bought $1 $2 for $3 $4 through Auction House.! 	0	79	9B	B0	FF			0	0	0	0	0		none
					/*CSystemMessage msg(2678);
					msg.AddNumber(priceAmount);
					msg.AddItem(priceId);
					msg.AddText(buyer);
					msg.AddNumber(amount);
					msg.AddItem(itemId);
					pUser->SendSystemMessage(&msg);*/

					//Send The main page of the board
					RequestShowAuction(pUser, 0, true);
				}
			}else
			{
				//347	1	a,Incorrect item count.\0	5	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,error\0
				pUser->pSocket->SendSystemMessage(347);
				RequestShowAuction(pUser, 0);
			}
		}
	}
	unguard;
	return false;
}


void CAuction::HandlePaymentRequest(User *pUser, INT32 priceId, INT32 priceAmount, INT32 itemId, INT32 amount, const WCHAR* buyer)
{
	guard;

	if(pUser->ValidUser())
	{

		pUser->PlaySound(L"ItemSound.quest_finish", 1, pUser->nObjectID, pUser->pSD->Pos.x, pUser->pSD->Pos.y, pUser->pSD->Pos.z);
		//2459	1	a,Incomming payment $s1 $s2 from $s3 for $s4 $s5 sold through Auction House.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
		CSystemMessage msg(2459);
		msg.AddNumber(priceAmount);
		msg.AddItem(priceId);
		msg.AddText(buyer);
		msg.AddNumber(amount);
		msg.AddItem(itemId);
		pUser->SendSystemMessage(&msg);

		CacheItemsMe(pUser, true);

		g_Logger.Add(L"Auction House payment[%d][%d] for user[%s] item[%d][%d]", priceId, priceAmount, pUser->pSD->wszName, itemId, amount);
	}

	unguard;
}

int CAuction::CalcEnchDef(UINT BaseDef, UINT enchant)
{
	int DefAddon = 0;
	if(enchant < 4)
	{
		DefAddon = enchant*1;
	}
	else
	{
		enchant = enchant-3;
		DefAddon = (enchant*3) + 3;
	}

	BaseDef = BaseDef + DefAddon;
	return BaseDef;
}

int CAuction::CalcEnchPAtk(UINT BasePAtk, UINT enchant, WeaponType nWeaponType, SlotType nSlotType, UINT nGrade)
{
	int PatkAddon = 0;
	if(nGrade == 1) //D Grade
	{
		if( nWeaponType == WeaponSword || nWeaponType == WeaponBlunt || nWeaponType == WeaponDagger || nWeaponType == WeaponPole || nWeaponType == WeaponDualFist )
		{
			if(enchant < 4)
			{
				PatkAddon = enchant*2;
			}
			else
			{
				enchant = enchant-3;
				PatkAddon = (enchant*4) + 6;
			}
		}
		else if( nWeaponType == WeaponBow )
		{
			if(enchant < 4)
			{
				PatkAddon = enchant*4;
			}
			else
			{
				enchant = enchant-3;
				PatkAddon = (enchant*8) + 12;
			}
		}
	}

	if(nGrade == 3 || nGrade == 2) //B-C Grade
	{
		if( (nWeaponType == WeaponSword && nSlotType == SlotRightHand ) || (nWeaponType == WeaponBlunt && nSlotType == SlotRightHand ) || nWeaponType == WeaponDagger || nWeaponType == WeaponPole )
		{
			if(enchant < 4)
			{
				PatkAddon = enchant*3;
			}
			else
			{
				enchant = enchant-3;
				PatkAddon = (enchant*6) + 9;
			}
		}
		else if( (nWeaponType == WeaponSword && nSlotType == SlotRightLeftHand ) || (nWeaponType == WeaponBlunt && nSlotType == SlotRightLeftHand ) || nWeaponType == WeaponDualFist)
		{
			if(enchant < 4)
			{
				PatkAddon = enchant*4;
			}
			else
			{
				enchant = enchant-3;
				PatkAddon = (enchant*8) + 12;
			}
		}
		else if( nWeaponType == WeaponBow )
		{
			if(enchant < 4)
			{
				PatkAddon = enchant*6;
			}
			else
			{
				enchant = enchant-3;
				PatkAddon = (enchant*12) + 18;
			}
		}
	}

	if(nGrade == 4) //A Grade
	{
		if( (nWeaponType == WeaponSword && nSlotType == SlotRightHand ) || (nWeaponType == WeaponBlunt && nSlotType == SlotRightHand ) || nWeaponType == WeaponDagger || nWeaponType == WeaponPole )
		{
			if(enchant < 4)
			{
				PatkAddon = enchant*4;
			}
			else
			{
				enchant = enchant-3;
				PatkAddon = (enchant*8) + 12;
			}
		}
		else if( (nWeaponType == WeaponSword && nSlotType == SlotRightLeftHand ) || (nWeaponType == WeaponBlunt && nSlotType == SlotRightLeftHand ) || nWeaponType == WeaponDualFist)
		{
			if(enchant < 4)
			{
				PatkAddon = enchant*5;
			}
			else
			{
				enchant = enchant-3;
				PatkAddon = (enchant*10) + 15;
			}
		}
		else if( nWeaponType == WeaponBow )
		{
			if(enchant < 4)
			{
				PatkAddon = enchant*8;
			}
			else
			{
				enchant = enchant-3;
				PatkAddon = (enchant*16) + 24;
			}
		}
	}

	if(nGrade == 5) //S Grade
	{
		if( (nWeaponType == WeaponSword && nSlotType == SlotRightHand ) || (nWeaponType == WeaponBlunt && nSlotType == SlotRightHand ) || nWeaponType == WeaponDagger || nWeaponType == WeaponPole )
		{
			if(enchant < 4)
			{
				PatkAddon = enchant*3;
			}
			else
			{
				enchant = enchant-3;
				PatkAddon = (enchant*6) + 9;
			}
		}
		else if( (nWeaponType == WeaponSword && nSlotType == SlotRightLeftHand ) || (nWeaponType == WeaponBlunt && nSlotType == SlotRightLeftHand ) || nWeaponType == WeaponDualFist)
		{
			if(enchant < 4) 
			{
				PatkAddon = enchant*6;
			}
			else
			{
				enchant = enchant-3;
				PatkAddon = (enchant*12) + 18;
			}
		}
		else if( nWeaponType == WeaponBow )
		{
			if(enchant < 4)
			{
				PatkAddon = enchant*10;
			}
			else
			{
				enchant = enchant-3;
				PatkAddon = (enchant*20) + 30;
			}
		}
	}

	BasePAtk = BasePAtk + PatkAddon;
	return BasePAtk;
}

int CAuction::CalcEnchMAtk(UINT BaseMAtk, UINT enchant, WeaponType nWeaponType, SlotType nSlotType, UINT nGrade)
{
	int MatkAddon = 0;

	if(nGrade == 1) //D Grade
	{
		if(enchant < 4)
		{
			MatkAddon = enchant*2;
		}
		else
		{
			enchant = enchant-3;
			MatkAddon = (enchant*4) + 6;
		}
	}

	if(nGrade == 4 || nGrade == 3 || nGrade == 2 ) //A-B-C Grade
	{
		if(enchant < 4)
		{
			MatkAddon = enchant*3;
		}
		else
		{
			enchant = enchant-3;
			MatkAddon = (enchant*6) + 9;
		}
	}

	if(nGrade == 5) //S Grade
	{
		if(enchant < 4)
		{
			MatkAddon = enchant*4;
		}
		else
		{
			enchant = enchant-3;
			MatkAddon = (enchant*8) + 12;
		}
	}

	BaseMAtk = BaseMAtk + MatkAddon;
	return BaseMAtk;
}

wstring CAuction::GetGradeIcon(UINT gradeid)
{
	guard;

	wstringstream gradeicon;
	switch(gradeid)
	{
	case 0:
		{
			gradeicon << L""; 
			break;
		}
	case 1:
		{
			gradeicon << L"<img src=\"symbol.grade_d\" width=16 height=16>"; 
			break;
		}
	case 2:
		{
			gradeicon << L"<img src=\"symbol.grade_c\" width=16 height=16>"; 
			break;
		}
	case 3:
		{
			gradeicon << L"<img src=\"symbol.grade_b\" width=16 height=16>"; 
			break;
		}
	case 4:
		{
			gradeicon << L"<img src=\"symbol.grade_a\" width=16 height=16>"; 
			break;
		}
	case 5:
		{
			gradeicon << L"<img src=\"symbol.grade_s\" width=16 height=16>"; 
			break;
		}
	}
	unguard;
	return gradeicon.str();
}


wstring CAuction::GetItemDesc(CItemInformation* pInfo, UINT nItemEnchant, UINT nAugmentation, UINT nExpireTime)
{
	guard;
	wstringstream desc;
	if(pInfo)
	{
		wstring expire;
		if(nExpireTime > 0)
		{
			UINT expireTime = nExpireTime - time(0);
			UINT days = expireTime / 86400;
			expireTime = expireTime % 86400;
			UINT hours = expireTime / 3600;
			expireTime = expireTime % 3600;
			UINT minutes = expireTime / 60;
			wstringstream expireStream;
			// 6d2h3m
			if( days > 0 || hours > 0 || minutes > 0 ) { expireStream << L"The item will expired into: "; }
			if(days > 0)
			{
				expireStream << days << L"d";
			}
			if(hours > 0)
			{
				expireStream << hours << L"h";
			}
			if(minutes)
			{
				expireStream << minutes << L"m";
			}
			expire = expireStream.str();
			if(expire.size() == 0)
			{
				expire = L"The item is Expired!";
			}
		}

		if(pInfo->itemtype == ItemTypeAccessory) //Accessory (M.Def / Slot / Weight)
		{
			desc << L"<table width=375 height=150 border=0 bgcolor=000000 cellpadding=0 cellspacing=0>";
			desc << L"<tr><td width=375 height=15 align=center>M.Def: " << CalcEnchDef(pInfo->mdef,nItemEnchant) << L"</td></tr>"; //CalcEnchDef
			desc << L"<tr><td width=375 height=15 align=center>Weight: " << pInfo->weight << L"</td></tr>";

			if(nExpireTime)
				desc << L"<tr><td width=375 height=15 align=center>" << expire << L"</td></tr>";
			else
				desc << L"<tr><td width=375 height=15 align=center></td></tr>";

			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"</table>";
		}
		if(pInfo->itemtype == ItemTypeArmor) //Armor (P.Def / Slot / Weight)
		{
			desc << L"<table width=375 height=150 border=0 bgcolor=000000 cellpadding=0 cellspacing=0>";
			if(!wcscmp(g_ItemDBEx.GetItemSA(pInfo->id).c_str(), L""))
			{
				desc << L"<tr><td width=375 height=15 align=center>P.Def: " << CalcEnchDef(pInfo->pdef,nItemEnchant) << L"</td></tr>";
			}
			else
			{
				desc << L"<tr><td width=375 height=15 align=center>Item SA: " << g_ItemDBEx.GetItemSA(pInfo->id) << L"</td></tr>";
				desc << L"<tr><td width=375 height=15 align=center>P.Def: " << CalcEnchDef(pInfo->pdef,nItemEnchant) << L"</td></tr>";
			}
			desc << L"<tr><td width=375 height=15 align=center>Weight: " << pInfo->weight << L"</td></tr>";

			if(nExpireTime)
				desc << L"<tr><td width=375 height=15 align=center>" << expire << L"</td></tr>";
			else
				desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"</table>";
		}
		if(pInfo->itemtype == ItemTypeEtc && (pInfo->etcitemtype == EtcItemPetCollar || pInfo->etcitemtype == EtcItemPetArmor) ) //Pet Good (Weight) -pet colar enchant=pet lvl
		{
			desc << L"<table width=375 height=150 border=0 bgcolor=000000 cellpadding=0 cellspacing=0>";
			desc << L"<tr><td width=375 height=15 align=center>Weight: " << pInfo->weight << L"</td></tr>";

			if(nExpireTime)
				desc << L"<tr><td width=375 height=15 align=center>" << expire << L"</td></tr>";
			else
				desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"</table>";
		}
		if(pInfo->itemtype == ItemTypeEtc && !(pInfo->etcitemtype == EtcItemPetCollar || pInfo->etcitemtype == EtcItemPetArmor)) //Supply (Weight)
		{
			desc << L"<table width=375 height=150 border=0 bgcolor=000000 cellpadding=0 cellspacing=0>";
			desc << L"<tr><td width=375 height=15 align=center>Weight: " << pInfo->weight << L"</td></tr>";

			if(nExpireTime)
				desc << L"<tr><td width=375 height=15 align=center>" << expire << L"</td></tr>";
			else
				desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"</table>";
		}
		if(pInfo->itemtype == ItemTypeWeapon) //Weapon (SA / Augment / P.Atk / M.Atk / Slot / Weight)
		{
			desc << L"<table width=375 height=150 border=0 bgcolor=000000 cellpadding=0 cellspacing=0>";

			desc << L"<tr><td width=375 height=15 align=center>P. Atk: " << CalcEnchPAtk(pInfo->patk,nItemEnchant,pInfo->weapontype,pInfo->slot,pInfo->grade) << L"</td></tr>";
			desc << L"<tr><td width=375 height=15 align=center>M. Atk: " << CalcEnchMAtk(pInfo->matk,nItemEnchant,pInfo->weapontype,pInfo->slot,pInfo->grade) << L"</td></tr>";
			desc << L"<tr><td width=375 height=15 align=center>Weight: " << pInfo->weight << L"</td></tr>";

			if(!wcscmp(g_ItemDBEx.GetItemSA(pInfo->id).c_str(), L""))
			{
				desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			}
			else
			{
				desc << L"<tr><td width=375 height=15 align=center>Weapon SA: " << g_ItemDBEx.GetItemSA(pInfo->id) << L"</td></tr>";
			}

			if(nAugmentation)
			{
				desc << L"<tr><td width=375 height=15 align=center>Augmentation Effect 1: " << g_Augmentation.GetName(g_Augmentation.GetFirstEffectID(nAugmentation)) << L"</td></tr>";
				desc << L"<tr><td width=375 height=15 align=center>Augmentation Effect 2: " << g_Augmentation.GetName(g_Augmentation.GetSecondEffectID(nAugmentation)) << L"</td></tr>";
			}
			else
			{
				desc << L"<tr><td width=375 height=15 align=center></td></tr>";
				desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			}
			if(nExpireTime)
				desc << L"<tr><td width=375 height=15 align=center>" << expire << L"</td></tr>";
			else
				desc << L"<tr><td width=375 height=15 align=center></td></tr>";
			desc << L"</table>";
		}
	}
	else
	{
		desc << L"<table width=375 height=150 border=0 bgcolor=000000 cellpadding=0 cellspacing=0><tr><td></br></td></tr></table>";
	}

	unguard;
	return desc.str();
}

wstring CAuction::GetCurrencyName(UINT m_CurrencyId)
{
	guard;
	for(map<UINT, SellCurrency>::iterator it = m_SellCurrency.begin(); it!= m_SellCurrency.end(); it++)
	{
		if( it->first == m_CurrencyId )
		{
			SellCurrency& sc = it->second;
			unguard;
			return sc.itemName;
		}
	}

	unguard;
	return L"";
}

UINT CAuction::GetCurrencyId(wstring m_CurrencyName, bool trim)
{
	guard;

	for(map<UINT, SellCurrency>::iterator it = m_SellCurrency.begin(); it!= m_SellCurrency.end(); it++)
	{
		SellCurrency& sc = it->second;
		wstring m_CurrencyDB(sc.itemName);
		if(!wcscmp(m_CurrencyDB.c_str(),m_CurrencyName.c_str()))
		{
			unguard;
			return it->first;
		}
		m_CurrencyDB = Utils::ReplaceString(m_CurrencyDB, L" ", L"", true);
		if(!wcscmp(m_CurrencyDB.c_str(),m_CurrencyName.c_str()))
		{
			unguard;
			return it->first;
		}
	}

	unguard;
	return 0;
}

wstring CAuction::GetCurrencyHtml(UINT m_CurrencyId)
{
	guard;
	for(map<UINT, SellCurrency>::iterator it = m_SellCurrency.begin(); it!= m_SellCurrency.end(); it++)
	{
		if( it->first == m_CurrencyId )
		{
			SellCurrency& sc = it->second;
			unguard;
			return sc.htmlstring;
		}
	}

	unguard;
	return L"";
}

bool CAuction::SetSpecsGrade(User *pUser, wstring wGrade)
{
	guard;

	//All;S;A;B;C;D;None
	if(!wcscmp(wGrade.c_str(), L"All"))
		pUser->pED->m_AuctionSearchGrade = 0;
	else if(!wcscmp(wGrade.c_str(), L"None"))
		pUser->pED->m_AuctionSearchGrade = 1;
	else if(!wcscmp(wGrade.c_str(), L"D"))
		pUser->pED->m_AuctionSearchGrade = 2;
	else if(!wcscmp(wGrade.c_str(), L"C"))
		pUser->pED->m_AuctionSearchGrade = 3;
	else if(!wcscmp(wGrade.c_str(), L"B"))
		pUser->pED->m_AuctionSearchGrade = 4;
	else if(!wcscmp(wGrade.c_str(), L"A"))
		pUser->pED->m_AuctionSearchGrade = 5;
	else if(!wcscmp(wGrade.c_str(), L"S"))
		pUser->pED->m_AuctionSearchGrade = 6;
	else 
		pUser->pED->m_AuctionSearchGrade = 0;

	RequestShowAuction(pUser, 0, true);

	unguard;
	return false;
}

bool CAuction::SetSpecsCat(User *pUser, wstring wCategory)
{
	guard;

	if(!wcscmp(wCategory.c_str(), L"All"))
	{
		pUser->pED->m_AuctionSearchCategory = 0;
		pUser->pED->m_AuctionSearchSubCategory = 0;
	}
	else if(!wcscmp(wCategory.c_str(), L"Accessory"))
	{
		pUser->pED->m_AuctionSearchCategory = 1;
		pUser->pED->m_AuctionSearchSubCategory = 0;
	}
	else if(!wcscmp(wCategory.c_str(), L"Armor"))
	{
		pUser->pED->m_AuctionSearchCategory = 2;
		pUser->pED->m_AuctionSearchSubCategory = 0;
	}
	else if(!wcscmp(wCategory.c_str(), L"PetGood"))
	{
		pUser->pED->m_AuctionSearchCategory = 3;
		pUser->pED->m_AuctionSearchSubCategory = 0;
	}
	else if(!wcscmp(wCategory.c_str(), L"Supply"))
	{
		pUser->pED->m_AuctionSearchCategory = 4;
		pUser->pED->m_AuctionSearchSubCategory = 0;
	}
	else if(!wcscmp(wCategory.c_str(), L"Weapon"))
	{
		pUser->pED->m_AuctionSearchCategory = 5;
		pUser->pED->m_AuctionSearchSubCategory = 0;
	}
	else
	{
		pUser->pED->m_AuctionSearchCategory = 0;
		pUser->pED->m_AuctionSearchSubCategory = 0;
	}

	RequestShowAuction(pUser, 0, true);

	unguard;
	return false;
}

bool CAuction::SetSpecsSubCat(User *pUser, wstring wSubCategory)
{
	guard;

	UINT m_Category = pUser->pED->m_AuctionSearchCategory;

	if(m_Category == 1) //Accessory
	{
		if(!wcscmp(wSubCategory.c_str(), L"All"))
			pUser->pED->m_AuctionSearchSubCategory = 0;
		else if(!wcscmp(wSubCategory.c_str(), L"Ring"))
			pUser->pED->m_AuctionSearchSubCategory = 1;
		else if(!wcscmp(wSubCategory.c_str(), L"Earring"))
			pUser->pED->m_AuctionSearchSubCategory = 2;
		else if(!wcscmp(wSubCategory.c_str(), L"Necklace"))
			pUser->pED->m_AuctionSearchSubCategory = 3;
		else if(!wcscmp(wSubCategory.c_str(), L"Hair"))
			pUser->pED->m_AuctionSearchSubCategory = 4;
		else
			pUser->pED->m_AuctionSearchSubCategory = 0;
	}
	else if(m_Category == 2) //Armor
	{
		if(!wcscmp(wSubCategory.c_str(), L"All"))
			pUser->pED->m_AuctionSearchSubCategory = 0;
		else if(!wcscmp(wSubCategory.c_str(), L"Helmet"))
			pUser->pED->m_AuctionSearchSubCategory = 1;
		else if(!wcscmp(wSubCategory.c_str(), L"Chest"))
			pUser->pED->m_AuctionSearchSubCategory = 2;
		else if(!wcscmp(wSubCategory.c_str(), L"Legs"))
			pUser->pED->m_AuctionSearchSubCategory = 3;
		else if(!wcscmp(wSubCategory.c_str(), L"Gloves"))
			pUser->pED->m_AuctionSearchSubCategory = 4;
		else if(!wcscmp(wSubCategory.c_str(), L"Shoes"))
			pUser->pED->m_AuctionSearchSubCategory = 5;
		else if(!wcscmp(wSubCategory.c_str(), L"Shield"))
			pUser->pED->m_AuctionSearchSubCategory = 6;
		else if(!wcscmp(wSubCategory.c_str(), L"Cloak"))
			pUser->pED->m_AuctionSearchSubCategory = 7;
		else
			pUser->pED->m_AuctionSearchSubCategory = 0;
	}
	else if(m_Category == 3) //PetGood
	{
		if(!wcscmp(wSubCategory.c_str(), L"All"))
			pUser->pED->m_AuctionSearchSubCategory = 0;
		else if(!wcscmp(wSubCategory.c_str(), L"Pet"))
			pUser->pED->m_AuctionSearchSubCategory = 1;
		else if(!wcscmp(wSubCategory.c_str(), L"Gear"))
			pUser->pED->m_AuctionSearchSubCategory = 2;
		else
			pUser->pED->m_AuctionSearchSubCategory = 0;
	}
	else if(m_Category == 4) //Supply
	{
		if(!wcscmp(wSubCategory.c_str(), L"All"))
			pUser->pED->m_AuctionSearchSubCategory = 0;
		else if(!wcscmp(wSubCategory.c_str(), L"Dye"))
			pUser->pED->m_AuctionSearchSubCategory = 1;
		else if(!wcscmp(wSubCategory.c_str(), L"Scroll"))
			pUser->pED->m_AuctionSearchSubCategory = 2;
		else if(!wcscmp(wSubCategory.c_str(), L"SACrystal"))
			pUser->pED->m_AuctionSearchSubCategory = 3;
		else if(!wcscmp(wSubCategory.c_str(), L"LifeStone"))
			pUser->pED->m_AuctionSearchSubCategory = 4;
		else if(!wcscmp(wSubCategory.c_str(), L"KeyMaterial"))
			pUser->pED->m_AuctionSearchSubCategory = 5;
		else if(!wcscmp(wSubCategory.c_str(), L"Material"))
			pUser->pED->m_AuctionSearchSubCategory = 6;
		else if(!wcscmp(wSubCategory.c_str(), L"Recipe"))
			pUser->pED->m_AuctionSearchSubCategory = 7;
		else if(!wcscmp(wSubCategory.c_str(), L"Miscellaneous"))
			pUser->pED->m_AuctionSearchSubCategory = 8;
		else if(!wcscmp(wSubCategory.c_str(), L"Spellbook"))
			pUser->pED->m_AuctionSearchSubCategory = 9;
		else
			pUser->pED->m_AuctionSearchSubCategory = 0;
	}
	else if(m_Category == 5) //Weapon
	{
		if(!wcscmp(wSubCategory.c_str(), L"All"))
			pUser->pED->m_AuctionSearchSubCategory = 0;
		else if(!wcscmp(wSubCategory.c_str(), L"Sword"))
			pUser->pED->m_AuctionSearchSubCategory = 1;
		else if(!wcscmp(wSubCategory.c_str(), L"BigSword"))
			pUser->pED->m_AuctionSearchSubCategory = 2;
		else if(!wcscmp(wSubCategory.c_str(), L"Blunt"))
			pUser->pED->m_AuctionSearchSubCategory = 3;
		else if(!wcscmp(wSubCategory.c_str(), L"BigBlunt"))
			pUser->pED->m_AuctionSearchSubCategory = 4;
		else if(!wcscmp(wSubCategory.c_str(), L"Dagger"))
			pUser->pED->m_AuctionSearchSubCategory = 5;
		else if(!wcscmp(wSubCategory.c_str(), L"Bow"))
			pUser->pED->m_AuctionSearchSubCategory = 6;
		else if(!wcscmp(wSubCategory.c_str(), L"Pole"))
			pUser->pED->m_AuctionSearchSubCategory = 7;
		else if(!wcscmp(wSubCategory.c_str(), L"Fists"))
			pUser->pED->m_AuctionSearchSubCategory = 8;
		else if(!wcscmp(wSubCategory.c_str(), L"Other"))
			pUser->pED->m_AuctionSearchSubCategory = 9;
		else if(!wcscmp(wSubCategory.c_str(), L"Duals"))
			pUser->pED->m_AuctionSearchSubCategory = 10;
		else
			pUser->pED->m_AuctionSearchSubCategory = 0;
	}
	else if(m_Category == 0)
	{
		pUser->pED->m_AuctionSearchSubCategory = 0;
	}

	RequestShowAuction(pUser, 0, true);

	unguard;
	return false;
}

bool CAuction::SetSpecsItemName(User *pUser, wstring wItemName)
{
	guard;

	pUser->pED->wAuctionSearchItemName = wItemName;

	RequestShowAuction(pUser, 0, true);

	unguard;
	return false;
}

bool CAuction::SetSpecsClear(User *pUser)
{
	guard;

	pUser->pED->m_AuctionSearchGrade = 0;
	pUser->pED->m_AuctionSearchCategory = 0;
	pUser->pED->m_AuctionSearchSubCategory = 0;
	pUser->pED->wAuctionSearchItemName = L"";

	RequestShowAuction(pUser, 0, true);

	unguard;
	return false;
}

wstring CAuction::ShowSearchPanel(User *pUser)
{
	guard;
	wstringstream wPanel;

	UINT m_SearchGrade = pUser->pED->m_AuctionSearchGrade;
	UINT m_SearchCat = pUser->pED->m_AuctionSearchCategory;
	UINT m_SearchSubCat = pUser->pED->m_AuctionSearchSubCategory; //0 = no dialog - 10 = dialog
	wstring wItemName = pUser->pED->wAuctionSearchItemName;

	wstring wGrade;
	if(m_SearchGrade == 0)
		wGrade = L"All";
	else if(m_SearchGrade == 1)
		wGrade = L"None";
	else if(m_SearchGrade == 2)
		wGrade = L"D";
	else if(m_SearchGrade == 3)
		wGrade = L"C";
	else if(m_SearchGrade == 4)
		wGrade = L"B";
	else if(m_SearchGrade == 5)
		wGrade = L"A";
	else if(m_SearchGrade == 6)
		wGrade = L"S";

	wstring wCat;
	if(m_SearchCat == 0)
		wCat = L"All";
	else if(m_SearchCat == 1)
		wCat = L"Accessory";
	else if(m_SearchCat == 2)
		wCat = L"Armor";
	else if(m_SearchCat == 3)
		wCat = L"Pet Good";
	else if(m_SearchCat == 4)
		wCat = L"Supply";
	else if(m_SearchCat == 5)
		wCat = L"Weapon";

	wPanel << L"<tr><td align=center></td></tr>";
	wPanel << L"<tr><td align=center></br></td></tr>";
	wPanel << L"<tr><td align=center>Grade: <font color=\"ff8000\">" << wGrade << L"</font></td></tr>";
	wPanel << L"<tr><td align=center><br1></td></tr>";
	wPanel << L"<tr><td align=center><combobox width=100 var=\"grade\" list=\"All;S;A;B;C;D;None\"></td></tr>";
	wPanel << L"<tr><td align=center><br1></td></tr>";
	wPanel << L"<tr><td align=center><button value=\"Apply\" action=\"bypass auct_sear_gr?grade= $grade\" width=64 height=19 back=\"L2UI_CH3.smallbutton2_down\" fore=\"L2UI_CH3.smallbutton2\"></td></tr>";
	wPanel << L"<tr><td align=center><br1></td></tr>";
	wPanel << L"<tr><td align=center>Category: <font color=\"ff8000\">" << wCat << L"</font></td></tr>";
	wPanel << L"<tr><td align=center><br1></td></tr>";
	wPanel << L"<tr><td align=center><combobox width=140 var=\"cat\" list=\"All;Accessory;Armor;Pet Good;Supply;Weapon\"></td></tr>";
	wPanel << L"<tr><td align=center><br1></td></tr>";
	wPanel << L"<tr><td align=center><button value=\"Apply\" action=\"bypass auct_sear_cat?cat= $cat\" width=64 height=19 back=\"L2UI_CH3.smallbutton2_down\" fore=\"L2UI_CH3.smallbutton2\"></td></tr>";
	wPanel << L"<tr><td align=center><br1></td></tr>";

	if(m_SearchCat == 1 ||  m_SearchCat == 2 || m_SearchCat == 3 || m_SearchCat == 4 || m_SearchCat == 5)
	{
		wstring wSubCats;
		wstring wSubCatsChoose;
		if(m_SearchCat == 1)
		{
			wSubCats = L"All;Ring;Earring;Necklace;Hair";
			if(m_SearchSubCat == 0)
				wSubCatsChoose = L"All";
			else if(m_SearchSubCat == 1)
				wSubCatsChoose = L"Ring";
			else if(m_SearchSubCat == 2)
				wSubCatsChoose = L"Earring";
			else if(m_SearchSubCat == 3)
				wSubCatsChoose = L"Necklace";
			else if(m_SearchSubCat == 4)
				wSubCatsChoose = L"Hair";
		}
		else if(m_SearchCat == 2)
		{
			wSubCats = L"All;Helmet;Chest;Legs;Gloves;Shoes;Shield;Cloak";
			if(m_SearchSubCat == 0)
				wSubCatsChoose = L"All";
			else if(m_SearchSubCat == 1)
				wSubCatsChoose = L"Helmet";
			else if(m_SearchSubCat == 2)
				wSubCatsChoose = L"Chest";
			else if(m_SearchSubCat == 3)
				wSubCatsChoose = L"Legs";
			else if(m_SearchSubCat == 4)
				wSubCatsChoose = L"Gloves";
			else if(m_SearchSubCat == 5)
				wSubCatsChoose = L"Shoes";
			else if(m_SearchSubCat == 6)
				wSubCatsChoose = L"Shield";
			else if(m_SearchSubCat == 7)
				wSubCatsChoose = L"Cloak";
		}
		else if(m_SearchCat == 3)
		{
			wSubCats = L"All;Pet;Gear";
			if(m_SearchSubCat == 0)
				wSubCatsChoose = L"All";
			else if(m_SearchSubCat == 1)
				wSubCatsChoose = L"Pet";
			else if(m_SearchSubCat == 2)
				wSubCatsChoose = L"Gear";
		}
		else if(m_SearchCat == 4)
		{
			wSubCats = L"All;Dye;Scroll;SA Crystal;Life Stone;Key Material;Material;Recipe;Spellbook;Miscellaneous"; //Spellbook
			if(m_SearchSubCat == 0)
				wSubCatsChoose = L"All";
			else if(m_SearchSubCat == 1)
				wSubCatsChoose = L"Dye";
			else if(m_SearchSubCat == 2)
				wSubCatsChoose = L"Scroll";
			else if(m_SearchSubCat == 3)
				wSubCatsChoose = L"SA Crystal";
			else if(m_SearchSubCat == 4)
				wSubCatsChoose = L"Life Stone";
			else if(m_SearchSubCat == 5)
				wSubCatsChoose = L"Key Material";
			else if(m_SearchSubCat == 6)
				wSubCatsChoose = L"Material";
			else if(m_SearchSubCat == 7)
				wSubCatsChoose = L"Recipe";
			else if(m_SearchSubCat == 8)
				wSubCatsChoose = L"Miscellaneous";
			else if(m_SearchSubCat == 9)
				wSubCatsChoose = L"Spellbook";
		}
		else if(m_SearchCat == 5)
		{
			wSubCats = L"All;Sword;Big Sword;Blunt;Big Blunt;Dagger;Bow;Pole;Fists;Duals;Other";
			if(m_SearchSubCat == 0)
				wSubCatsChoose = L"All";
			else if(m_SearchSubCat == 1)
				wSubCatsChoose = L"Sword";
			else if(m_SearchSubCat == 2)
				wSubCatsChoose = L"Big Sword";
			else if(m_SearchSubCat == 3)
				wSubCatsChoose = L"Blunt";
			else if(m_SearchSubCat == 4)
				wSubCatsChoose = L"Big Blunt";
			else if(m_SearchSubCat == 5)
				wSubCatsChoose = L"Dagger";
			else if(m_SearchSubCat == 6)
				wSubCatsChoose = L"Bow";
			else if(m_SearchSubCat == 7)
				wSubCatsChoose = L"Pole";
			else if(m_SearchSubCat == 8)
				wSubCatsChoose = L"Fists";
			else if(m_SearchSubCat == 9)
				wSubCatsChoose = L"Other";
			else if(m_SearchSubCat == 10)
				wSubCatsChoose = L"Duals";
		}

		wPanel << L"<tr><td align=center>Sub-Category: <font color=\"ff8000\">" << wSubCatsChoose << L"</font></td></tr>";
		wPanel << L"<tr><td align=center><br1></td></tr>";
		wPanel << L"<tr><td align=center><combobox width=140 var=\"scat\" list=\"" << wSubCats << L"\"></td></tr>";
		wPanel << L"<tr><td align=center><br1></td></tr>";
		wPanel << L"<tr><td align=center><button value=\"Apply\" action=\"bypass auct_sear_subcat?subc= $scat\" width=64 height=19 back=\"L2UI_CH3.smallbutton2_down\" fore=\"L2UI_CH3.smallbutton2\"></td></tr>";
		wPanel << L"<tr><td align=center><br1></td></tr>";
	}

	wPanel << L"<tr><td align=center>Item Name: <font color=\"ff8000\">" << wItemName << L"</font></td></tr>";
	wPanel << L"<tr><td align=center><br1></td></tr>";
	wPanel << L"<tr><td align=center><edit var=\"item_name\" width=110></td></tr>";
	wPanel << L"<tr><td align=center><br1></td></tr>";
	wPanel << L"<tr><td align=center><button value=\"Apply\" action=\"bypass auct_sear_itemn?itemn= $item_name\" width=64 height=19 back=\"L2UI_CH3.smallbutton2_down\" fore=\"L2UI_CH3.smallbutton2\"></td></tr>";
	

	if(m_SearchSubCat == 1 ||  m_SearchSubCat == 2 || m_SearchSubCat == 3 || m_SearchSubCat == 4 || m_SearchSubCat == 5)
		wPanel << L"<tr><td align=center></br></br></br></td></tr>";
	else
		wPanel << L"<tr><td align=center></br></br></br></br></br></br></td></tr>";
				
	wPanel << L"<tr><td align=center><button value=\"Clear Search\" action=\"bypass auct_sear_clear\" width=95 height=21 back=\"l2ui_ch3.bigbutton_down\" fore=\"l2ui_ch3.bigbutton\"></td></tr>";
		
	unguard;
	return  wPanel.str();
}