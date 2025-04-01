#pragma once

struct tmEx : tm
{
	bool operator< (const tm& other) const
	{
		//year
		if(tm_year < other.tm_year)
			return true;
		if(tm_year > other.tm_year)
			return false;
		//month
		if(tm_mon < other.tm_mon)
			return true;
		if(tm_mon > other.tm_mon)
			return false;
		//day
		if(tm_mday < other.tm_mday)
			return true;
		if(tm_mday > other.tm_mday)
			return false;
		//hour
		if(tm_hour < other.tm_hour)
			return true;
		if(tm_hour > other.tm_hour)
			return false;
		//minute
		if(tm_min < other.tm_min)
			return true;
		if(tm_min > other.tm_min)
			return false;
		//sec
		if(tm_sec < other.tm_sec)
			return true;
		
		return false;
	}

	bool operator> (const tm& other) const
	{
		//year
		if(tm_year > other.tm_year)
			return true;
		if(tm_year < other.tm_year)
			return false;
		//month
		if(tm_mon > other.tm_mon)
			return true;
		if(tm_mon < other.tm_mon)
			return false;
		//day
		if(tm_mday > other.tm_mday)
			return true;
		if(tm_mday < other.tm_mday)
			return false;
		//hour
		if(tm_hour > other.tm_hour)
			return true;
		if(tm_hour < other.tm_hour)
			return false;
		//minute
		if(tm_min > other.tm_min)
			return true;
		if(tm_min < other.tm_min)
			return false;
		//sec
		if(tm_sec > other.tm_sec)
			return true;
		
		return false;
	}
};

class CNpcSpawnDefine
{
	int npcClassId;
	int x;
	int y;
	int z;
	int heading;

	int x2;
	int y2;
	int z2;
	int heading2;

	int x3;
	int y3;
	int z3;
	int heading3;

	time_t startDate;
	time_t endDate;
	bool dayFlag[7];
	int startHour;
	int startMinute;
	int endHour;	//0-23
	unsigned int respawnTime; //in seconds
	bool saveInDB;
	time_t spawnTime;
	time_t deathTime;
	unsigned int npcObjectId;
	map<wstring, wstring> ai_parameters;
	friend class CNpcMaker;
public:
	CNpcSpawnDefine();
};

class CNpcSpawnEventDefine
{
	int eventID;
	bool spawned;
	string eventName;
	time_t startDate;
	time_t endDate;
	bool dayFlag[7];
	int startHour;
	int startMinute;
	int endHour;	//0-23
	//wstring AnnounceSpawn;
	//wstring AnnounceDeSpawn;
	friend class CNpcMaker;
public:
	CNpcSpawnEventDefine();
};

typedef vector<CNpcSpawnDefine> SpawnDefineList;
typedef vector<CNpcSpawnEventDefine> SpawnEventDefineList;

class CNpcMaker
{
	CRITICAL_SECTION lock;
	SpawnDefineList lData;
	SpawnEventDefineList lData2;
	bool loadedFromDB;
	bool requestedDB;
	bool requestReload;
	BOOL m_enabled;
	__forceinline void Lock() { EnterCriticalSection(&lock); };
	__forceinline void Unlock() { LeaveCriticalSection(&lock); };
public:
	CNpcMaker();
	~CNpcMaker();
	void Initialize();
	void SetLoadedFromDB(bool Value);
	void ReadData();
	time_t GetFixedSpawnTime(tmEx startTime, time_t spawnTime, DWORD spawnReuse);
	void LoadedFromDB(int npcClassId, DWORD deathTime);
	void TimerExpired();
	void SpawnTick(CNpcSpawnDefine& spawnDefine);
	void SpawnEventTick(CNpcSpawnEventDefine& spawnDefine);
	void DespawnTick(CNpcSpawnDefine& spawnDefine);
	void DespawnEventTick(CNpcSpawnEventDefine& spawnDefine);
	void TickForNormal(CNpcSpawnDefine& spawnDefine);
	void TickForStartDate(CNpcSpawnDefine& spawnDefine);
	void TickForStartDay(CNpcSpawnDefine& spawnDefine);
	void OnNpcDie(CNPC *pNPC, bool locked = false);
	void DespawnAll();
	void SpawnNpc(CNpcSpawnDefine& data);
	void DespawnNpc(CNpcSpawnDefine& data);
	void ByPassTeleport(User* pUser);
	void SetRequestReload();
	bool BlockTeleportNpcPosEx(wstring wName);
};

extern CNpcMaker g_NpcMaker;