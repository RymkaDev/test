#pragma once

struct VisualArmorInfo
{
	UINT armorType;
	int chestSlotId;
	int legsSlotId;
	int glovesSlotId;
	int feetSlotId;
	int hairSlotId;
	int minLevel;
	int maxLevel;
	int itemVerify;
	wstring item_icon;
	ItemReq price;

	VisualArmorInfo() : armorType(0), chestSlotId(0), legsSlotId(0), glovesSlotId(0), feetSlotId(0), hairSlotId(0), minLevel(0), maxLevel(0), itemVerify(0) {};
};

class CVisualArmor
{
	CSLock m_Lock;
	bool m_Enabled;
	bool m_CheckBodyParts;
	int m_RequiredItemID;
	int m_RequiredItemQuanity;
	map<UINT, VisualArmorInfo*> m_Armors;
	time_t m_ReloadTick;
	void LoadData();
public:
	CVisualArmor();
	~CVisualArmor();
	void Init();
	void ShowMenu(User *pUser);
	void OnRequestEquip(User *pUser);
	VisualArmorInfo* Get(UINT armorId);
	void OnEquip(User *pUser, UINT armorId);
	bool OnTradeTest(UINT itemId, UINT armorId);
	void OnUnequip(User *pUser);
	void TimerExpired();
	inline void RequestReload() { m_ReloadTick = time(0) + 1; m_Enabled = FALSE; };
	inline bool IsEnabled() { return m_Enabled; };
	inline bool CheckBodyParts() { return m_CheckBodyParts; };
	void OnEquipTest(User *pUser, UINT armorId);
};

extern CVisualArmor g_VisualArmor;