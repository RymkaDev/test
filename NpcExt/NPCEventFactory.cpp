#include "stdafx.h"
#include "NPCEventFactory.h"



void CNPCEventFactory::Init()
{
	ItemsDroppedAIMultiplierLoad();

	WriteCall(0x5DD420, CNPCEventFactory::CreateDeletePreviousOlympiadPointReturned, 0);
	WriteJump(0x5DD464, 0x5DD48C, 3);



	WriteJump(0x4C317B, (UINT64)CNPCEventFactory::GiveItem1);
}

LPVOID CNPCEventFactory::CreateDeletePreviousOlympiadPointReturned(CNPC *pNpc, User *pTalker, int nPoint, int nReturned)
{
	if(nPoint > 0)
	{
		typedef LPVOID (*f)(CNPC*, User*, int, int);
		return f(0x5428E0L)(pNpc, pTalker, nPoint, nReturned);
	}else
	{
		g_Log.Add(LogError, "[%s] Point[%d] - CHEATER[%S]!", __FUNCTION__, nPoint, pTalker->pSD->wszName);
	}
	return 0;
}



LPVOID CNPCEventFactory::GiveItem1(DWORD* _this, CSharedCreatureData* c, int nItemClassID, int nCount)
{

	double amount_double = static_cast<double>(nCount);
	amount_double *= CNPCEventFactory::ItemDropAIMultiplier(nItemClassID);
	nCount = static_cast<int>(amount_double);


	//if(nItemClassID == 7079)
		//nCount *= 10;

	typedef LPVOID (*f)(DWORD*, CSharedCreatureData*, int, int);
	return f(0x4EDC10L)(_this, c, nItemClassID, nCount);

}


	map<INT32, double> m_ItemDropAIMultiplier;

double CNPCEventFactory::ItemDropAIMultiplier(int itemid)
{
	for(map<INT32, double>::iterator it = m_ItemDropAIMultiplier.begin(); it!= m_ItemDropAIMultiplier.end(); it++)
	{
		if(it->first == itemid)
		{
			return it->second;
		}
	}

	//g_Log.Add(LogError, "return 1", __FUNCTION__);
	return 1;
}


void CNPCEventFactory::ItemsDroppedAIMultiplierLoad()
{	
	m_ItemDropAIMultiplier.clear();

	wstring filew = ReadFileW(L"..\\Script\\ItemsDroppedAIMultiplier.txt");
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
					double multi = Parser::ParseOptionDouble(line, L"multiplier", 1);

					if(itemId > 0)
					{
						//g_Log.Add(LogError, "[%s] [%d][%f] !", __FUNCTION__, itemId, multi);
						m_ItemDropAIMultiplier.insert(pair<INT32, double>(itemId, multi));
					}
				}
			}
		}
	}else
	{
		//g_Log.Add(LogError, "[%s] Cannot find ..//Script//ItemsDroppedAIMultiplier.txt !", __FUNCTION__);
	}
}
	