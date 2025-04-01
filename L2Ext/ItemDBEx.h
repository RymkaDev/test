#pragma once

class CItemDBEx;

class CItemDataEx
{
	int item_id;
	int shadow_time;
	int reuse_group;
	friend class CItemDBEx;
public:
	CItemDataEx() : item_id(0), shadow_time(0), reuse_group(0) { }
	__forceinline void Set(int ItemID, int ShadowTime, int ReuseGroup) { item_id = ItemID; shadow_time = ShadowTime; reuse_group = ReuseGroup; }
	__forceinline int GetItemID() { return item_id; };
	__forceinline int GetShadowTime() { return shadow_time;}
	__forceinline int GetReuseGroup() { return reuse_group; }
};

struct ItemExSkillList
{
	vector<CSkillKey> m_Skills;
	INT32 m_maxStackableLevel;
	INT32 m_stackType;
	CItemDataEx* *pExData;
};
/*
struct ItemInfo
{
	INT32 id;
	wstring name;
	ItemType itemtype;
	UINT pdef;
	UINT mdef;
	UINT patk;
	UINT matk;
	UINT pdef_sh;
	SlotType slot;
	UINT weight;
	CrystalType grade;
	EtcItemType etcitemtype;
	UINT is_trade;
	UINT is_drop;
	UINT is_destruct;
	UINT magic_wep;

	ItemInfo() : id(0), itemtype(ItemTypeEtc), pdef(0), mdef(0), patk(0), matk(0), pdef_sh(0), slot(SlotNone), weight(0), grade(CrystalNone), etcitemtype(EtcItemNone), is_trade(0), is_drop(0), is_destruct(0), magic_wep(0)  {}
};
*/

class CItemInformation
{
public:
	INT32 id;
	wstring name;
	ItemType itemtype;
	UINT pdef;
	UINT mdef;
	UINT patk;
	UINT matk;
	UINT pdef_sh;
	SlotType slot;
	UINT weight;
	CrystalType grade;
	EtcItemType etcitemtype;
	WeaponType weapontype;
	UINT is_trade;
	UINT is_drop;
	UINT is_destruct;
	UINT magic_wep;
	wstring clientname;

	CItemInformation() : id(0), itemtype(ItemTypeEtc), pdef(0), mdef(0), patk(0), matk(0), pdef_sh(0), slot(SlotNone), weight(0), grade(CrystalNone), etcitemtype(EtcItemNone), weapontype(WeaponNone), is_trade(0), is_drop(0), is_destruct(0), magic_wep(0)  {}
};

class CItemDBEx : private CThreadSafe
{
	map<int, CItemDataEx*> mData;
	map<INT32, wstring> m_ItemName;
	map<INT32, wstring> m_ItemSA;
	map<INT32, wstring> m_ItemIcon;
	map<INT32, UINT> m_LifeTime;
	//New Maps
	map<INT32, wstring> m_ItemPch;
	//vector<ItemInfo*> m_Items;
	vector<pair<UINT, CItemInformation*>> m_Items;

public:
	CItemDBEx();
	~CItemDBEx();
	void Init();
	void LoadItemName();
	void LoadItemGrp();
	wstring GetItemName(int itemId);
	wstring GetItemSA(int itemId);
	wstring GetItemIcon(int itemId);
	void ReadData();
	void Clear();
	CItemDataEx* GetItemDataEx(int item_id);
	UINT GetLifeTime(int itemId);
	void ReadDataItemPch();
	void ReadDataItemData();
	CItemInformation* GetItemInfo(UINT itemID);
	bool ItemCanBeSold(UINT itemID);
};

extern CItemDBEx g_ItemDBEx;