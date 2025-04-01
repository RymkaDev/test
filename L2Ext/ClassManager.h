#pragma once

class CClassManager
{
	BOOL m_enabled;
	INT32 m_requiredItemId[3];
	INT32 m_requiredItemCount[3];
	INT32 m_ThirdChangeSoloEnUltima;
	
	
	INT32 m_required3ItemId;
	INT32 m_required3ItemCount;

	BOOL m_changeEnabled[3];
	ItemReq m_ChangeReward[3];
	BOOL m_Nobless;
	INT32 m_NoblessPriceId;
	INT32 m_NoblessPriceAmount;
	INT32 m_NoblessLevel;
	BOOL m_SubClass;
	INT32 m_SubClassPriceId;
	INT32 m_SubClassPriceAmount;
	BOOL m_Karma;
	INT32 m_KarmaPriceId;
	INT32 m_KarmaPriceAmount;

	BOOL m_SubClass2;
	INT32 m_SubClass2Price1Id;
	INT32 m_SubClass2Price1Amount;
	INT32 m_SubClass2Price2Id;
	INT32 m_SubClass2Price2Amount;
	INT32 m_SubClass2Price3Id;
	INT32 m_SubClass2Price3Amount;
	INT32 m_SubClass2Price4Id;
	INT32 m_SubClass2Price4Amount;
	INT32 m_SubClass2Price5Id;
	INT32 m_SubClass2Price5Amount;
	INT32 m_SubClass2RewardId;
	INT32 m_SubClass2RewardAmount;

	BOOL m_SubClass3;
	INT32 m_SubClass3PriceId;
	INT32 m_SubClass3PriceAmount;
	INT32 m_SubClass3RewardId;
	INT32 m_SubClass3RewardAmount;

	BOOL m_Nobless2;
	INT32 m_Nobless2PriceId;
	INT32 m_Nobless2PriceAmount;
	INT32 m_Nobless2Price2Id;
	INT32 m_Nobless2Price2Amount;

	map<INT32, wstring> m_class_name;
	void LoadClassName();
public:
	CClassManager();
	~CClassManager();
	void Init();
	wstring GetName(INT32 classId);
	void GetAvailable(int baseClassId, list<int>& lAvailable);
	bool CanChange(User *pUser, int newClass);
	void RequestShowHtml(User *pUser);
	void RequestChange(User *pUser, int newClass);
	void RequestNobless(User *pUser);
	void RequestNobless2(User *pUser);
	void RequestSubClass(User *pUser);
	void RequestSubClass2(User *pUser);
	void RequestSubClass3(User *pUser);
	void RequestKarma(User *pUser, int karma);
};

extern CClassManager g_ClassManager;