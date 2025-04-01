#pragma once

class COfflineShop
{
	BOOL m_Enabled;
	BOOL m_AutoActivate;
	BOOL m_StayInGame;
	BOOL m_ConsumeRequiredItem;
	int m_RequiredItemId;
	int m_RequiredItemCount;
	BOOL m_SaveOnDBStores;
	BOOL m_SaveOnDBBuffers;
	BOOL m_SaveOnDBUsers;
	UINT m_ShopTimeLimit;
	int m_IpMacLimit;
	int m_RequiredItemPriceId;
	int m_RequiredItemPriceCount;
	BOOL m_AutoLogoutPlayer;
	//CRITICAL_SECTION _lock;

public:
	static const int OFFLINE_SHOP_ABNORMAL = 180;	//not used
	static const int OFFLINE_SHOP_USER_COMMAND = 114;
	void Initialize();
	static void OnSocketRead(CUserSocket* pSocket, LPVOID p2 );
	void RequestActivateOfflineShop(User *pUser,bool isbuffer=false);
	void RequestBuyRequiredItem(User *pUser);
	bool IsOfflineShop(CUserSocket *pSocket);
	void TimerExpired(User *pUser);
	void AutoActivate(User *pUser);
	//inline bool GetTimeLimitUser() { return m_ShopTimeLimit2; };
	static int AuthKick(User *pUser);
	static void BuilderCmdKick(CUserSocket *pSocket);
	static void KickCharPacket(CUserSocket *pSocket);
	static bool ManageCloseTimer(CIOObject *pIOObject, int nTimeSpan, int nTimerID);
	static void AddToStatusWindow(LPVOID pWindow, int nLine, PWCHAR format, int nCount);
	static void OnWho(LPWSTR wcsBuffer, LPCWSTR wcsFormat,... );
	static bool PrivateMessageA(User *pUser, int nSenderDBID);
	static void PrivateMessageB(CUserSocket *pSocket, int nMsgID, PWCHAR wsName);

	inline BOOL SaveOnDbStores() { return m_SaveOnDBStores; };
	inline BOOL SaveOnDbBuffers() { return m_SaveOnDBBuffers; };
	inline BOOL SaveOnDbUsers() { return m_SaveOnDBUsers; };
};

extern COfflineShop g_OfflineShop;