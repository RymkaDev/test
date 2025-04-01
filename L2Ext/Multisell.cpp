#include "StdAfx.h"
#include "MultiSell.h"
#include "ObjectDB.h"

CMultiSellDB g_MultiSellDB;

vector<INT32> BlockedDuplicateBuyItem;

extern BOOL g_Servidor_beta_multisell_free;

CMultiSellEntry::CMultiSellEntry(wstring wLine)
{
	if(wLine.find(L"{{{") == 0)
	{
		//{{{[flamberge];1}};{{[crystal_c];573};{[crystal_d];2865}}};
		PARSE_STATE PState = MS_BEGIN;
		wstring wName;
		wstring wCount;
		for(int n=0;n<wLine.size();n++)
		{
			switch(PState)
			{
			case MS_BEGIN:
				if(wLine[n] == '{')
				{
					PState = MS_REWARD;
				}
				break;
			case MS_REWARD:
				if(wLine[n] == '[')
				{
					PState = MS_REWARD_NAME;
					break;
				}
				if(wLine[n] == '}')
				{
					PState = MS_PRICE;
					break;
				}
				break;
			case MS_REWARD_NAME:
				if(wLine[n] == ';')
				{
					PState = MS_REWARD_COUNT;
					break;
				}
				if(wLine[n] == ']')
					break;
				wName += wLine[n];
				break;
			case MS_REWARD_COUNT:
				if(wLine[n] == '}')
				{
					CMultiSellItem Item(g_ObjectDB.GetClassIdFromName(wName.c_str()), _wtoi(wCount.c_str()));
					wName = L"";
					wCount = L"";
					vReward.push_back(Item);
					PState = MS_REWARD;
					break;
				}
				wCount += wLine[n];
				break;
			case MS_PRICE:
				if(wLine[n] == '[')
				{
					PState = MS_PRICE_NAME;
					break;
				}
				if(wLine[n] == '}')
				{
					PState = MS_END;
					break;
				}
				break;
			case MS_PRICE_NAME:
				if(wLine[n] == ';')
				{
					PState = MS_PRICE_COUNT;
					break;
				}
				if(wLine[n] == ']')
					break;
				wName += wLine[n];
				break;
			case MS_PRICE_COUNT:
				if(wLine[n] == '}')
				{
					CMultiSellItem Item(g_ObjectDB.GetClassIdFromName(wName.c_str()), _wtoi(wCount.c_str()));
					wName = L"";
					wCount = L"";
					vPrice.push_back(Item);
					PState = MS_PRICE;
					break;
				}
				wCount += wLine[n];
				break;
			case MS_END:
				break;
			}
		}
	}
}
size_t CMultiSellEntry::GetPriceItemCount() 
{ 
	return vPrice.size(); 
};
size_t CMultiSellEntry::GetRewardItemCount() 
{ 
	return vReward.size(); 
};

CMultiSell::CMultiSell() : ID(0), is_dutyfree(false), is_show_all(false), keep_enchanted(false)
{

};

void CMultiSell::Begin(wstring wLine)
{
	//MultiSell_begin	[blackmerchant_weapon]	1
	wstringstream sstr;
	sstr << wLine;
	sstr >> wName;
	sstr >> wName; //real name
	sstr >> ID;
}
int CMultiSell::GetID()
{
	return ID;
}
size_t CMultiSell::GetEntryCount()
{
	return vEntry.size();
}
void CMultiSell::Clear()
{
	is_dutyfree = false;
	is_show_all = false;
	keep_enchanted = false;
	wName = L"";
	ID = 0;
	vEntry.clear();
}
void CMultiSell::SetOption(wstring wLine)
{
	if(wLine.find(L"is_dutyfree")==0)
	{
		wLine = CParser::Trim(wLine);
		size_t pos = wLine.find('=');
		wstring wOpt = wLine.substr(pos+1, 1);
		if(wOpt == L"1")
			is_dutyfree = true;
		else
			is_dutyfree = false;
	}else if(wLine.find(L"is_show_all")==0)
	{
		wLine = CParser::Trim(wLine);
		size_t pos = wLine.find('=');
		wstring wOpt = wLine.substr(pos+1, 1);
		if(wOpt == L"1")
			is_show_all = true;
		else
			is_show_all = false;
	}else if(wLine.find(L"keep_enchanted")==0)
	{
		wLine = CParser::Trim(wLine);
		size_t pos = wLine.find('=');
		wstring wOpt = wLine.substr(pos+1, 1);
		if(wOpt == L"1")
			keep_enchanted = true;
		else
			keep_enchanted = false;
	}
}
void CMultiSell::AddEntry(wstring wLine)
{
	CMultiSellEntry Entry(wLine);
	if(Entry.vReward.size() > 0)
	{
		vEntry.push_back(Entry);


		if(Entry.vPrice.size() == 1)
		{
			for(vector<CMultiSellItem>::iterator Iter = Entry.vPrice.begin();Iter!=Entry.vPrice.end();Iter++)
			{

				if (Iter->ItemID == 57)
				{
					CItem *pItem = g_ObjectDB.GetTemplateObject(Iter->ItemID)->SafeCastItem();
					if(pItem)
					{
						int nPrice = Iter->Count;

						for(vector<CMultiSellItem>::iterator Iter2 = Entry.vReward.begin();Iter2!=Entry.vReward.end();Iter2++)
						{
							if(Iter2->ItemID > 0)
							{
								CItem *pItem2 = g_ObjectDB.GetTemplateObject(Iter2->ItemID)->SafeCastItem();
								if(pItem2)
								{
									int DefaultPrice = pItem2->pII->defaultPrice;

									if (nPrice < DefaultPrice)
										g_Log.Add(CLog::Error, "[%s] REVISAR PRECIO!!!! - nPrice[%d] DefaultPrice[%d] [%S]", __FUNCTION__, nPrice, DefaultPrice, wLine.c_str());
			
								}else
								{
									g_Log.Add(CLog::Error, "[%s] Cannot find vReward[%d]", __FUNCTION__, Iter2->ItemID);
								}
							}
						}

					}else
					{
						g_Log.Add(CLog::Error, "[%s] Cannot find vPrice[%d]", __FUNCTION__, Iter->ItemID);
					}
				}
			}
		}

/*///////////////////////////////////////////////////////////////////////
		//validate for adena mistakes
		INT64 AdenaPrice = 0;
		INT64 AdenaReward = 0;

		//price:
		for(vector<CMultiSellItem>::iterator Iter = Entry.vPrice.begin();Iter!=Entry.vPrice.end();Iter++)
		{
			//CItem *pItem = CObjectDB::GetObject(Iter->ItemID)->CastItem();

			CItem *pItem = CObject::GetObjectBySID(Iter->ItemID)->SafeCastItem();
			if(pItem)
			{
				int DefaultPrice = pItem->pII->defaultPrice;
				if(DefaultPrice < 1)
					DefaultPrice = 1;
				AdenaPrice += ( DefaultPrice * Iter->Count);
			}else
			{
				g_Log.Add(CLog::Error, "[%s] Cannot find item[%d]", __FUNCTION__, Iter->ItemID);
			}
		}

		//reward
		for(vector<CMultiSellItem>::iterator Iter = Entry.vReward.begin();Iter!=Entry.vReward.end();Iter++)
		{
			//CItem *pItem = CObjectDB::GetObject(Iter->ItemID)->CastItem();
			CItem *pItem = CObject::GetObjectBySID(Iter->ItemID)->SafeCastItem();
			if(pItem)
			{
				int DefaultPrice = pItem->pII->defaultPrice;
				if(DefaultPrice < 1)
					DefaultPrice = 1;
				AdenaReward += ( DefaultPrice * Iter->Count);
			}else
			{
				g_Log.Add(CLog::Error, "[%s] Cannot find item[%d]", __FUNCTION__, Iter->ItemID);
			}
		}

		if(AdenaReward > (AdenaPrice * 2))
		{
			wLine = CParser::Replace(wLine, L'\n', L'');
			g_Log.Add(CLog::Error, "[%s] Reward bigger than price!!", __FUNCTION__);
			g_Log.Add(CLog::Error, "%S", wLine.c_str());
		}
	///////////////////////////////////////////////////////////////////////////*/
	}
}

void CMultiSellDB::Init()
{
	ReadData();
	g_HookManager.WriteCall(0x69293F, CMultiSellDB::SendList, 0);
	g_HookManager.WriteCall(0x692A37, CMultiSellDB::SendList, 0);
	g_HookManager.WriteCall(0x692B04, CMultiSellDB::SendList, 0);
	g_HookManager.WriteCall(0x692CA6, CMultiSellDB::SendList, 0);

	g_HookManager.WriteCall(0x868620, CMultiSellDB::MultiSellChoose, 0);
}

void CMultiSellDB::ReadData()
{
	wstring str = ReadFileW(g_ChangeFolders.MultiSell_txt);
	wstringstream sstr;
	sstr << str;
	wstring wLine;
	CMultiSell MultiSell;
	while(getline(sstr, wLine))
	{
		if(wLine.find(L"//") == 0)
			continue;
		else if(wLine.find(L"MultiSell_begin") == 0)
		{
			MultiSell.Begin(wLine);
		}else if(wLine.find(L"is_dutyfree") == 0)
		{
			MultiSell.SetOption(wLine);
		}else if(wLine.find(L"is_show_all") == 0)
		{
			MultiSell.SetOption(wLine);
		}else if(wLine.find(L"keep_enchanted") == 0)
		{
			MultiSell.SetOption(wLine);
		}else if(wLine.find(L"{{{") == 0 )
		{
			MultiSell.AddEntry(wLine);
		}else if(wLine.find(L"MultiSell_end") == 0)
		{
			mData.insert(pair<int, CMultiSell>(MultiSell.GetID(), MultiSell));
			MultiSell.Clear();
		}
	}
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] MultiSell lists.", __FUNCTION__, mData.size());



	BlockedDuplicateBuyItem.clear();

	TCHAR temp[0x4000];
	if(GetPrivateProfileString(_T("MULTISELL"), _T("BlockedDuplicateBuyItem"), 0, temp, 0x8000, g_CustomConfigFile))
	{
		tstringstream sstr;
		sstr << temp;
		INT32 itemId = 0;
		while(sstr >> itemId)
		{
			BlockedDuplicateBuyItem.push_back(itemId);
		}
	}

	g_Log.Add(CLog::Blue, "[%s] Loaded BlockedDuplicateBuyItem [%d]", __FUNCTION__, BlockedDuplicateBuyItem.size());

}

int CMultiSellDB::ConvertEntry(UINT nEntryID, int nItemCount)
{
	UINT nConv = 0;
	nItemCount*=2;
	nConv = (((nEntryID % nItemCount)+1)/2)-1;
	
	return nConv;
}

bool CMultiSellDB::GetPriceAndReward(UINT listId, UINT entryId, INT32 count, LPINT lpPriceId, LPINT lpPriceCount, LPINT lpRewardId, LPINT lpRewardCount)
{
	guard;
	
	map<INT32, CMultiSell>::iterator it = mData.find(listId);
	if(it!=mData.end())
	{
		UINT entryIndex = ConvertEntry(entryId, (INT32)it->second.GetEntryCount());
		if(entryIndex < it->second.GetEntryCount())
		{
			CMultiSellEntry& entry = it->second.vEntry[entryIndex];
			for(INT32 n=0;n<entry.vPrice.size();n++)
			{
				if(n < 5)
				{
					lpPriceId[n] = entry.vPrice[n].GetID();
					lpPriceCount[n] = entry.vPrice[n].GetCount() * count;
				}
			}
			for(INT32 n=0;n<entry.vReward.size();n++)
			{
				if(n < 5)
				{
					lpRewardId[n] = entry.vReward[n].GetID();
					lpRewardCount[n] = entry.vReward[n].GetCount() * count;
				}
			}
			unguard;
			return true;
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Invalid entry index[%d] - entry[%d][%d] list[%d]", __FUNCTION__, entryIndex, entryId, it->second.GetEntryCount(), listId);
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Cannot find MultiSell! ListId[%d]", __FUNCTION__, listId);
	}

	unguard;
	return false;
}

bool CMultiSellDB::Validate(User *pUser, int nListID, int nItemIndex, int nAmount)
{
	if(pUser->ValidUser() && nAmount && nItemIndex >= 0)
	{
		try
		{
			int PetItemId = 0;
			map<int, CMultiSell>::iterator Iter = mData.find(nListID);
			if(Iter!=mData.end())
			{
				nItemIndex = ConvertEntry(nItemIndex, (int)Iter->second.GetEntryCount());
				if(nItemIndex < Iter->second.GetEntryCount())
				{

					//check price int overflow
					int nPriceSize = (int)Iter->second.vEntry[nItemIndex].GetPriceItemCount();
					for(int n=0;n<nPriceSize;n++)
					{
						INT64 nFinalPrice = ((INT64)nAmount) * ((INT64)Iter->second.vEntry[nItemIndex].vPrice[n].Count);
						if( nFinalPrice > (INT64)2100000000 || nFinalPrice < 0)
						{
							g_Log.Add(CLog::Error, "[%s] int overflow - multisell price amount[%d] entry[%d] item[%d]", __FUNCTION__, nAmount, nItemIndex, n);
							return false;
						}
					}
					//check reward int overflow
					int nRewardSize = (int)Iter->second.vEntry[nItemIndex].GetRewardItemCount();
					for(int n=0;n<nRewardSize;n++)
					{
						INT64 nFinalPrice = ((INT64)nAmount) * ((INT64)Iter->second.vEntry[nItemIndex].vReward[n].Count);
						if( nFinalPrice > (INT64)2100000000 || nFinalPrice < 0)
						{
							g_Log.Add(CLog::Error, "[%s] int overflow - multisell reward amount[%d] entry[%d] item[%d]", __FUNCTION__, nAmount, nItemIndex, n);
							return false;
						}
						CItem *pItem = pUser->GetInventory()->GetFirstItemByClassID(Iter->second.vEntry[nItemIndex].vReward[n].ItemID);
						if(pItem->IsValidItem() && (pItem->pSID->nConsumeType == CItem::consume_type_asset || pItem->pSID->nConsumeType == CItem::consume_type_stackable))
						{
							INT64 nOwnedAmount = (INT64)pItem->pSID->nItemAmount;
							nOwnedAmount += nFinalPrice;
							if(nOwnedAmount > (INT64)2100000000 || nOwnedAmount < 0)
							{
								g_Log.Add(CLog::Error, "[%s] int overflow - multisell reward + owned - amount[%d] entry[%d] item[%d]", __FUNCTION__, nAmount, nItemIndex, n);
								return false;
							}
						}

						if(pItem->IsValidItem())
						{
							for(UINT z=0;z< BlockedDuplicateBuyItem.size();z++)
							{
								if(BlockedDuplicateBuyItem[z] == pItem->pSID->nItemID)
								{
									pUser->pSocket->SendSystemMessage(L"No puedes comprar este item porque ya tienes uno en el inventario.");
									return false;
								}
							}
						}

						if(Iter->second.vEntry[nItemIndex].vReward[n].ItemID == 9532)
						{
							CItem *pItem3 = pUser->GetInventory()->GetFirstItemByClassID(9449);
							if(pItem3->IsValidItem())
							{
								pUser->pSocket->SendSystemMessage(L"No puedes comprar este item porque ya tienes una runa en el inventario.");
								return false;
							}
						}

						for(UINT z=0;z< BlockedDuplicateBuyItem.size();z++)
						{
							if(BlockedDuplicateBuyItem[z] == Iter->second.vEntry[nItemIndex].vReward[z].ItemID && nAmount > 1)
							{
								pUser->pSocket->SendSystemMessage(L"Este item solamente lo puedes comprar de a uno.");
								return false;
							}
						}
					}

					//VENDER MASCOTAS EN MULTISELL
					int nSize = (int)Iter->second.vEntry[nItemIndex].GetPriceItemCount();
					if (nSize> 0)
					{
						int nItemId = (int)Iter->second.vEntry[nItemIndex].vPrice[0].ItemID;
						int nCount = (int)Iter->second.vEntry[nItemIndex].vPrice[0].Count;


						int nRSize = (int)Iter->second.vEntry[nItemIndex].GetRewardItemCount();
						if(nRSize>0)
						{
							int itemId = (int)Iter->second.vEntry[nItemIndex].vReward[0].ItemID;
							int itemIdCount = (int)Iter->second.vEntry[nItemIndex].vReward[0].Count;


							if( itemId == 2375 || itemId == 3500 || itemId == 3501 || itemId == 3502 || itemId == 4422 || itemId == 4423 || itemId == 4424 || itemId == 6648 || itemId == 6649 || itemId == 6650 || itemId == 4425 )
							{
								if(pUser->DeleteItemInInventory(nItemId, nCount))
								{
									if( itemId == 2375 ) //wolf
									{
										typedef void(*f)(User*, INT32, INT32, INT32);
										f(0x74BED0L)(pUser, itemId, 1012077, 78);
									}
									else if( itemId == 3500 ) // d wind
									{
										typedef void(*f)(User*, INT32, INT32, INT32);
										f(0x74BED0L)(pUser, itemId, 1012311, 78);
									}
									else if( itemId == 3501 ) // d star
									{
										typedef void(*f)(User*, INT32, INT32, INT32);
										f(0x74BED0L)(pUser, itemId, 1012312, 78);
									}
									else if( itemId == 3502 ) // d twil
									{
										typedef void(*f)(User*, INT32, INT32, INT32);
										f(0x74BED0L)(pUser, itemId, 1012313, 78);
									}
									else if( itemId == 4422 ) // b d wind
									{
										typedef void(*f)(User*, INT32, INT32, INT32);
										f(0x74BED0L)(pUser, itemId, 1012526, 78);
									}
									else if( itemId == 4423 ) // b d star
									{
										typedef void(*f)(User*, INT32, INT32, INT32);
										f(0x74BED0L)(pUser, itemId, 1012527, 78);
									}
									else if( itemId == 4424 ) // b d dusk
									{
										typedef void(*f)(User*, INT32, INT32, INT32);
										f(0x74BED0L)(pUser, itemId, 1012528, 78);
									}
									else if( itemId == 6648 ) // baby buffalo pan
									{
										typedef void(*f)(User*, INT32, INT32, INT32);
										f(0x74BED0L)(pUser, itemId, 1012780, 78);
									}
									else if( itemId == 6649 ) // baby cougar chime
									{
										typedef void(*f)(User*, INT32, INT32, INT32);
										f(0x74BED0L)(pUser, itemId, 1012782, 78);
									}
									else if( itemId == 6650 ) // baby kukaburo
									{
										typedef void(*f)(User*, INT32, INT32, INT32);
										f(0x74BED0L)(pUser, itemId, 1012781, 78);
									}
									else if( itemId == 4425 ) // sin eater
									{
										typedef void(*f)(User*, INT32, INT32, INT32);
										f(0x74BED0L)(pUser, itemId, 1012564, 78);
									}

									return false;
								}
							}


							if(g_Servidor_beta_multisell_free || pUser->pSD->nBuilder)
							{
								//COMPRA GRATIS
								pUser->AddItemToInventory(itemId, itemIdCount * nAmount);
								return false;
							}


						}
					}

					return true;

				}else
					g_Log.Add(CLog::Error, "[%s] Invalid ItemIndex[%d] in ListID[%d]", __FUNCTION__, nItemIndex, nListID);
			}else
				g_Log.Add(CLog::Error, "[%s] Invalid ListID[%d]", __FUNCTION__, nListID);
		}catch(...)
		{
			g_Log.Add(CLog::Blue, "[%s] Exception Detected - List[%d] ItemIndex[%d] Count[%d]", __FUNCTION__, nListID, nItemIndex, nAmount);
		}
	}
	return false;
}

void CMultiSellDB::MultiSellChoose(User *pUser, UINT groupId, int itemChooseId, int itemAmount)
{
	guard;
	if(pUser->pED->multiSellGroupId == groupId)
	{
		typedef void (*f)(User*, UINT, int, int);
		f(0x8489D0L)(pUser, groupId, itemChooseId, itemAmount);
	}else
	{
		g_Log.Add(CLog::Error, "[%s] Invalid groupId[%d] sent[%d] User[%S]!", __FUNCTION__, groupId, pUser->pED->multiSellGroupId, pUser->pSD->wszName);
	}
	unguard;
}

void CMultiSellDB::SendList(CUserSocket *pSocket, const char* format, BYTE opCode, UINT groupId, UINT page, UINT finished, UINT totalPages, UINT groupSize, DWORD buffLen, LPBYTE lpBuff)
{
	guard;
	if(User *pUser = pSocket->pUser->SafeCastUser())
	{
		pUser->pED->multiSellGroupId = groupId;
	//	g_Log.Add(CLog::Blue, "[%s] Player[%S] multisell group[%d]", __FUNCTION__, pUser->pSD->wszName, groupId);
		pSocket->Send(format, opCode, groupId, page, finished, totalPages, groupSize, buffLen, lpBuff);
	}
	unguard;
}

bool CMultiSellDB::SendListCustom(User *pUser, UINT listid)
{
	guard;
	if(pUser->ValidUser())
	{

	}
	unguard;
	return true;
}