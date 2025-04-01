#pragma once

struct OfflineBuffSkills
{
	UINT skill_id;
	UINT max_skill_level;
};

class COfflineBuffer
{
	BOOL m_Enabled;
	CSLock m_Lock;
	map<int, int> skills;
	int nTitleColor;
	int nTimeForShop;
	int nMinPrice;
	int nMaxPrice;
	int m_RequiredItemId;
	int m_RequiredItemCount;
	BOOL m_ConsumeRequiredItem;
	BOOL m_allowOnlySpecificZone;
	double m_MinDistance;

public:
	COfflineBuffer();
	~COfflineBuffer();
	void Initialize();
	void LoadData();
	void RequestActivateOfflineBuffShop(User *pUser);
	void EnableBuffer(User *pUser, wstring wTitle, int buffprice, bool normal_char = false);
	bool CheckClass(int classid);
	bool CheckBuff(int nSkillID);
	bool CheckBuffExist(User *pUser, int nSkillID);
	int GetBuffLevelFromUser(User *pUser, int nSkillID);
	void ShowOfflineBufferList(User *pAsker, User *pBuffer, UINT page, bool isforpet);
	void ShowOfflineBufferList2(User *pAsker, UINT charid, UINT page, bool isforpet);
	void BuyBuff(User *pBuyer, UINT nSkillID, UINT nSellerID, bool isforpet);
	bool IsOfflineBuffer(User *pUser);
	bool OfflineBufferStop(User *pUser);
	void CreatePages(User *pUser, bool isforpet);
	inline int GetOfflineBufferColor() { return nTitleColor; };
	inline int GetOfflineBufferTime() { return nTimeForShop; };
	inline double GetMinDistance() { return m_MinDistance; };

};

extern COfflineBuffer g_OfflineBuffer;