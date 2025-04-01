#pragma once


struct AutoAnnounceData
{
	wstring announce;
	BOOL onEnterWorld;
	time_t interval;	//in seconds
	time_t nextAnnounceTime;
	BOOL critAnnounce;
};

struct StaticAnnounceData
{
	wstring announce;
	BOOL critAnnounce;
	UINT hour;
	UINT min;
	BOOL jobdone;
	time_t nextjobreset;
	bool dayFlag[7];
};

class CAutoAnnounce
{
	CSLock m_lock;
	BOOL m_enabled;
	BOOL m_reload;
	BOOL m_SendMsg;
	UINT m_SendMsgEpicId;
	UINT m_SendMsgId;
	vector<AutoAnnounceData> m_data;
	vector<StaticAnnounceData> m_data2;
	wstring m_BossAnnounce;
	wstring m_BossAnnounce2;
	vector<INT32> m_BossList;
	vector<INT32> m_BossEpicList;

	wstring AnnounceOnBossSpawnAnticipo;
	UINT AnnounceOnBossAnticipoTime;

	BOOL m_SendMsgKill;
	UINT m_SendMsgKillEpicId;
	UINT m_SendMsgKillId;
	wstring m_AnnounceOnBossKillClan;
	wstring m_AnnounceOnBossKill;
	wstring m_AnnounceOnBossEpicKill;
	wstring m_AnnounceOnBossEpicKillClan;

	wstring m_AnnounceOnBossKillNobless;
	wstring m_AnnounceOnBossKillDarion;

	BOOL mDarNoblesPorMatarBarakiel;
	BOOL mDarEntradaPorMatarDarion;



	void LoadINI();
public:

	CAutoAnnounce();
	~CAutoAnnounce();
	inline void SetReload() { m_reload = TRUE; };
	void Init();
	void TimerExpired();
	void OnEnterWorld(User *pUser);
	void OnBossEnterWorld(UINT npcClassId);
	void OnBossKillWorld(UINT npcClassId, CCreature *pKiller);
};

extern CAutoAnnounce g_AutoAnnounce;