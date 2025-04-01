#pragma once

struct KillData
{
	UINT victimDatabaseId;
	UINT killTime;
};

class CKillDb
{
	CSLock m_Lock;
	map<UINT, vector<KillData>> m_Data;
	map<UINT, vector<KillData>> m_DataWar;
public:
	CKillDb();
	//bool IsInReuse(UINT killerId, UINT victimId, UINT reuse);
	bool IsInReuse(UINT killerId, UINT victimId, UINT reuse, bool war = false);
};

extern CKillDb g_KillDb;