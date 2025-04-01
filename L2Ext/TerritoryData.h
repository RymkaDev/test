#pragma once
#include "TerritoryEx.h"


class CTerritoryChecker
{
	protected:
		CRITICAL_SECTION clanUsersLock;
		CRITICAL_SECTION TerritoryLock;
		CRITICAL_SECTION PvPZoneUsersLock;
	private:
		inline void Lock() { EnterCriticalSection(&clanUsersLock); }
		inline void Unlock() { LeaveCriticalSection(&clanUsersLock); }

		inline void LockPvPZone() { EnterCriticalSection(&PvPZoneUsersLock); }
		inline void UnlockPvPZone() { LeaveCriticalSection(&PvPZoneUsersLock); }

		inline void LockTerritory() { EnterCriticalSection(&TerritoryLock); }
		inline void UnlockTerritory() { LeaveCriticalSection(&TerritoryLock); }
		map<int, CTerritoryEx*> mData;

public:
	CTerritoryChecker();
	~CTerritoryChecker();
	void Initialize();
	void ReadData(string sFile);
	void GetTerritories(CCreature *pCreature, TerritoryData& td);
	int IsInTerritory(CCreature *pCreature, TerritoryType type);
	int IsInTerritory(FVector& Pos, TerritoryType type);
	void ValidateRideTerritory(CCreature *pCreature);
	CTerritoryEx* GetTerritory(int ID);
	void AddZonePvP(int npcId, int x, int y, int z);
	void DeleteZonePvP(int npcId);

	void AddZonePvP2(int npcId, int x, int y, int z);
	void DeleteZonePvP2(int npcId);

	std::map<int, int> clanUserCountsMap;

	map<UINT, User*> m_users;

	std::map<UINT, User*> UsersInZonePvPMap;
	void AddUserPvPZone(User *pUser);
	void DelUserPvPZone(User *pUser);
	void AutoAttackPvPZone(User *pUser);

	int ClanIdMaxCounts;
	void updateClanUserCount(int clanId, int count);
	int getClanWithMaxUsers();
	int getClanUserCount(int clanId);
	void setClanUserCountTittle(User* pUser);
	void Res(User* pUser);
	void Die(User* pUser);
};

extern CTerritoryChecker g_TerritoryChecker;