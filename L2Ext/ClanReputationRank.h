#pragma once

class CClanReputationRank
{
	typedef struct {
		UINT pledgeId;
		wstring pledgeName;
		UINT raidCount;
		UINT raidRepCount;
	} RaidStatusClan;

	bool m_Enabled;
	CSLock m_Lock;
	time_t m_RefreshTimeout;
	time_t m_RefreshTime;

	UINT m_ResetDay;
	UINT m_ResetHour;
	UINT m_ResetMinute;
	time_t m_ResetTime;
	bool m_ResetDone;

	UINT m_PrizeId;
	UINT m_PrizeQuanity;

	UINT m_TopLimit;
	typedef vector<RaidStatusClan> StatusVector;
	StatusVector m_Status;
	vector<wstring> m_Pages;

public:
	void Init();
	void LoadINI();
	void TimerExpired();
	void OnDBLoadPvP(UINT pledgeId, UINT raidCount, UINT raidRepCount, const WCHAR* wName);
	void RequestClanRaidStatus(User *pUser, UINT page = 0);
	void SetWinner(UINT nPlace, UINT pledgeId, UINT raidbosscount, UINT raidbossRepcount, wstring pledgeName, UINT leaderId, wstring leaderName);
	void GeneratePagesRaid();
	inline bool Enabled() const { return m_Enabled; }
};

extern CClanReputationRank g_ClanReputationRank;