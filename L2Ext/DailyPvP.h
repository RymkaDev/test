#pragma once

#include "DBSocket.h"

struct DailyPvPInfo
{
	UINT charId;
	time_t timestmap;
	HWID hardwareId;
};

class CDailyPvP
{
	BOOL m_Enabled;
	INT32 m_RequiredPvP;
	INT32 m_MinLevel;
	INT32 m_ItemReward;
	INT32 m_ItemQuanity;
	BOOL m_HwidChk;
	BOOL m_CustomZone;
	INT32 m_MessageId;
	BOOL m_ShowPoints;
	INT32 m_Time;
	time_t m_CleanUpTimestamp;
	CSLock m_Lock;
	vector<DailyPvPInfo> m_DB;

public:

	void Init();
	void LoadINI();
	inline BOOL IsEnabled() { return m_Enabled; };
	void OnDBLoad(UINT charId, LPBYTE lpHWID, UINT timestamp);
	bool GetPoint(User *pKiller, User *pEnemy);
	void TimerExpired(User *pUser);
	void TimerExpired();
	void TerminarEvento();
	void ShowPoints(User *pUser);

	static bool ReplyWinners(CDBSocket *pSocket, const unsigned char* packet, UINT packetId);
};

extern CDailyPvP g_DailyPvP;