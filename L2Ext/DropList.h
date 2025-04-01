#pragma once

namespace NpcData
{
	struct ItemDropInfo
	{
		INT32 itemId;
		INT32 minCount;
		INT32 maxCount;
		double chance;
		bool stackable;
		INT32 groupId;
	};

	struct GroupDropInfo
	{
		vector<ItemDropInfo> items;
		double chance;
		double itemsChanceSum;
		BOOL adenaGroup;
	};

	struct NpcDropInfo
	{
		INT32 classId;	// npcId + 1000000
		vector<ItemDropInfo> itemMakeList;
		vector<ItemDropInfo> additionalMakeList;
		vector<GroupDropInfo> additionalMakeMultiList;
		vector<ItemDropInfo> DropListFull; //Only For Droplist
		vector<ItemDropInfo> SpoilListFull; //Only For Droplist
	};

	struct DropListHtml
	{
		vector<wstring> m_Pages;
	};

	class CDropList
	{
		BOOL m_enabled;
		BOOL m_enabledShift;
		BOOL m_debugMsg;
		BOOL m_SpellbooksDrop;
		double m_raidBossItemRate;
		double m_SealStoneRate;
		double m_ItemCountsRate;
		double m_SpoilCountsRate;
		list<int> itemsnotdropped;
		map<INT32, NpcDropInfo*> m_data;
		map<INT32, DropListHtml*> m_dataHtml;
		map<INT32, DropListHtml*> m_dataHtmlSpoil;
		void Release();
		void ParseNpcData(wstring line);
		bool ParseItemMakeList(vector<ItemDropInfo>& itemMakeList, wstring data);
		bool ParseAdditionalMakeList(vector<ItemDropInfo>& additionalMakeList, wstring data);
		bool ParseAdditionalMakeList2(vector<ItemDropInfo>& additionalMakeList, wstring data);
		bool ParseAdditionalMakeMultiList(vector<GroupDropInfo>& additionalMakeMultiList, wstring data);
		bool ParseAdditionalMakeMultiList2(vector<ItemDropInfo>& additionalMakeMultiList, wstring data, bool IsBoss);
		void LoadData();
		void ItemsNotDroppedLoad();
	public:
		CDropList();
		void Init();
		~CDropList();
		inline BOOL IsEnabled() { return m_enabled; };
		void OnDie(CNPC *pNpc, CCreature *pEnemy);
		bool ExistDroplist(UINT NpcId);
		void ShowDroplist(User *pUser, UINT NpcId, UINT page);
		void ShowSpoilDroplist(User *pUser, UINT NpcId, UINT page);
		void CreateHtmlDroplist(UINT NpcId, bool IsBoss);
		bool ItemForNotDrop(int itemid);
		
		inline bool IsShiftDroplistEnabled() { return m_enabledShift; };
		inline double GetSpoilCountsRate() { return m_SpoilCountsRate; };
	};
};

extern NpcData::CDropList g_DropList;