#pragma once

class DropRaidsCustom
{
	struct CustomItemDropInfo
	{
		INT32 itemId;
		INT32 minCount;
		INT32 maxCount;
		double chance;
	};

	struct CustomDropInfo
	{
		INT32 npcId;
		INT32 level_min;
		INT32 level_max;
		vector<CustomItemDropInfo> DropList;
	};

	enum CustomDropType
	{
		ALLBOSS = 1,
		ALLMOBS = 2,
	};

	struct CustomDroppedItems
	{
		INT32 itemId;
		INT32 Count;
	};


	struct CContributeDataForEvent
	{
	  CGeneralObject* cgeneralobject0;
	  CIOCriticalSection ciocriticalsection30;
	  BYTE gap60[8];
	  DWORD qword68;
	  DWORD qword69;
	  DWORD qword70;
	  DWORD qword71;
	  DWORD nObjectIDorPartyID;
	  BYTE gap7C[12];
	  DWORD qword88;
	  DWORD qword89;
	  DWORD qword90;
	  DWORD qword91;
	  BYTE gap98[4];
	  DWORD dword9C;
	  DWORD dwordA0;
		//BYTE estructura[168];
	};

	struct AtomicDropItem2
	{
	  UINT64 *base;
	  BYTE ASD[16];
	  unsigned int mNpcSID;
	  int mItemClassId;
	  int mItemCount;
	  FVector mvPos;
	  unsigned int mContributorID;
	};


	vector<CustomDropInfo> m_CustomDrop;

	public:
		void LoadINI();
		void Handle(CNPC* pNpc, CCreature* attacker);

};

extern DropRaidsCustom g_DropRaidsCustom;