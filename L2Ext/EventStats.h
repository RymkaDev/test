#pragma once

struct EventStatsInfo
{
	wstring name;
	UINT classId;
	INT32 level;
	INT32 killsAmount;
	INT32 deathsAmount;
};

class CEventStats
{
	BOOL m_Enabled;
	CSLock m_Lock;
	UINT m_RefreshTimeout;
	time_t m_RefreshTime;
	vector<EventStatsInfo> m_DBKills;
	vector<EventStatsInfo> m_DBDeaths;
	vector<wstring> m_PagesKills;
	vector<wstring> m_PagesDeaths;
	void LoadINI();
public:
	void Init();
	inline bool IsEnabled() { return m_Enabled; }

};

extern CEventStats g_EventStats;