#pragma once

class CNPCEventFactory
{
public:
	
	static void Init();

	static void ItemsDroppedAIMultiplierLoad();
	static double ItemDropAIMultiplier(int itemid);

	static LPVOID CreateDeletePreviousOlympiadPointReturned(CNPC *pNpc, User *pTalker, int nPoint, int nReturned);

	static LPVOID GiveItem1(DWORD* _this, CSharedCreatureData* c, int nItemClassID, int nCount);


};