#include "StdAfx.h"
#include "TerritoryData.h"


extern INT32 g_ZonePvPSpawnBossRadio;
extern BOOL g_ZonePvPSpawnBossBarakiel;


extern BOOL g_ZonePvPAutoAttackRejunte;
extern INT32 g_ZonePvPAutoAttackRejunteDist;
extern double g_ZonePvPAutoAttackRejunteDamage;
extern INT32 g_ZonePvPAutoAttackRejunteTimeProtection;
extern double g_ZonePvPAutoAttackRejunteMinimo;
extern double g_ZonePvPAutoAttackRejunteResta;


CTerritoryChecker::CTerritoryChecker()
{
	InitializeCriticalSection(&clanUsersLock);
	InitializeCriticalSection(&TerritoryLock);
	InitializeCriticalSection(&PvPZoneUsersLock);
}

CTerritoryChecker::~CTerritoryChecker()
{
	DeleteCriticalSection(&clanUsersLock);
	DeleteCriticalSection(&TerritoryLock);
	DeleteCriticalSection(&PvPZoneUsersLock);
}

void CTerritoryChecker::Initialize()
{
	g_Log.Add(CLog::Blue, "[%s] Loading Data...", __FUNCTION__);
	ReadData(g_ChangeFolders.TerritoryData_txt);
}



void CTerritoryChecker::DeleteZonePvP(int npcId)
{

	bool permitir = true;
	if(npcId == 1025325)		//blinding_fire_barakiel
	{
		if(!g_ZonePvPSpawnBossBarakiel)
			permitir = false;
	}

    if(g_ZonePvPSpawnBossRadio > 0 && permitir)
    {
		LockTerritory();
        int npcId1 = npcId + 100000000;
        int npcId2 = npcId + 200000000;

        std::map<int, CTerritoryEx*>::iterator it = mData.find(npcId1);
        if (it != mData.end()) {
            // Eliminar el objeto de memoria
            delete it->second;
            // Eliminar la entrada del mapa
            mData.erase(it);
        }

        std::map<int, CTerritoryEx*>::iterator it2 = mData.find(npcId2);
        if (it2 != mData.end()) {
            // Eliminar el objeto de memoria
            delete it2->second;
            // Eliminar la entrada del mapa
            mData.erase(it2);
        }
		UnlockTerritory();
    }
}

void CTerritoryChecker::AddZonePvP(int npcId, int x, int y, int z)
{
	bool permitir = true;
	if(npcId == 1025325)		//blinding_fire_barakiel
	{
		if(!g_ZonePvPSpawnBossBarakiel)
			permitir = false;
	}

    if(g_ZonePvPSpawnBossRadio > 0 && permitir)
    {
		LockTerritory();
        int x1 = x + g_ZonePvPSpawnBossRadio;
        int y1 = y + g_ZonePvPSpawnBossRadio;
        int z1 = z + g_ZonePvPSpawnBossRadio;

        int x2 = x - g_ZonePvPSpawnBossRadio;
        int y2 = y - g_ZonePvPSpawnBossRadio;
        int z2 = z - g_ZonePvPSpawnBossRadio;

        int npcId1 = npcId + 100000000;
        int npcId2 = npcId + 200000000;

        // Verificar y eliminar si npcId1 ya existe
        if(mData.count(npcId1) > 0) {
            delete mData[npcId1];
        }

        CTerritoryEx *pTerritory = new CTerritoryEx();
        pTerritory->Set(x2, x1, y2, y1, z2, z1, PVP_ZONE);
        mData[npcId1] = pTerritory;  // Asignación directa

        // Verificar y eliminar si npcId2 ya existe
        if(mData.count(npcId2) > 0) {
            delete mData[npcId2];
        }

        CNickNameChangeTerritory *pTerritory2 = new CNickNameChangeTerritory();
        pTerritory2->Set(x2, x1, y2, y1, z2, z1, NICKNAME_CHANGE_ZONE);
        pTerritory2->SetColor(16711935);
		pTerritory2->SetHidePledge(0);

		string sName;
		wchar_t wName[512]; memset(wName, 0, sizeof(wName));
		_AnsiToUnicode(sName.c_str(), wName);
		pTerritory2->SetNickName(wName);

        mData[npcId2] = pTerritory2;  // Asignación directa
		UnlockTerritory();
    }
}









void CTerritoryChecker::DeleteZonePvP2(int npcId)
{
//	if(npcId == 1025325)		//blinding_fire_barakiel
    if(g_ZonePvPSpawnBossRadio > 0)
    {
		LockTerritory();
        int npcId1 = npcId + 100000000;
        int npcId2 = npcId + 200000000;

        std::map<int, CTerritoryEx*>::iterator it = mData.find(npcId1);
        if (it != mData.end()) {
            // Eliminar el objeto de memoria
            delete it->second;
            // Eliminar la entrada del mapa
            mData.erase(it);
        }

        std::map<int, CTerritoryEx*>::iterator it2 = mData.find(npcId2);
        if (it2 != mData.end()) {
            // Eliminar el objeto de memoria
            delete it2->second;
            // Eliminar la entrada del mapa
            mData.erase(it2);
        }
		UnlockTerritory();
    }
}

void CTerritoryChecker::AddZonePvP2(int npcId, int x, int y, int z)
{
	//if(npcId == 1025325)		//blinding_fire_barakiel

    if(g_ZonePvPSpawnBossRadio > 0)
    {
		LockTerritory();
        int x1 = x + g_ZonePvPSpawnBossRadio;
        int y1 = y + g_ZonePvPSpawnBossRadio;
        int z1 = z + g_ZonePvPSpawnBossRadio;

        int x2 = x - g_ZonePvPSpawnBossRadio;
        int y2 = y - g_ZonePvPSpawnBossRadio;
        int z2 = z - g_ZonePvPSpawnBossRadio;

        int npcId1 = npcId + 100000000;
        int npcId2 = npcId + 200000000;

        // Verificar y eliminar si npcId1 ya existe
        if(mData.count(npcId1) > 0) {
            delete mData[npcId1];
        }

        CTerritoryEx *pTerritory = new CTerritoryEx();
        pTerritory->Set(x2, x1, y2, y1, z2, z1, PVP_ZONE);
        mData[npcId1] = pTerritory;  // Asignación directa

        // Verificar y eliminar si npcId2 ya existe
        if(mData.count(npcId2) > 0) {
            delete mData[npcId2];
        }

        CNickNameChangeTerritory *pTerritory2 = new CNickNameChangeTerritory();
        pTerritory2->Set(x2, x1, y2, y1, z2, z1, NICKNAME_CHANGE_ZONE);
        pTerritory2->SetColor(16711935);
		pTerritory2->SetHidePledge(0);

		string sName;
		wchar_t wName[512]; memset(wName, 0, sizeof(wName));
		_AnsiToUnicode(sName.c_str(), wName);
		pTerritory2->SetNickName(wName);

        mData[npcId2] = pTerritory2;  // Asignación directa
		UnlockTerritory();
    }
}




// Función para actualizar la cantidad de personas para un clan en la zona
void CTerritoryChecker::updateClanUserCount(int clanId, int count) {

	Lock();
    clanUserCountsMap[clanId] += count;
	Unlock();

	ClanIdMaxCounts = getClanWithMaxUsers();
}

void CTerritoryChecker::AddUserPvPZone(User *pUser)
{
	if(g_ZonePvPAutoAttackRejunte)
	{
		if(pUser->ValidUser())
		{
			LockPvPZone();
			try
			{
				pUser->pED->nInCustomAntiRejunteZoneTime = time(0) + g_ZonePvPAutoAttackRejunteTimeProtection;
				UsersInZonePvPMap.insert(pair<UINT, User*>(pUser->nDBID, pUser));
			}catch(...)
			{
				EXCEPTION_LOG;
			}
			UnlockPvPZone();
		}
	}
}


void CTerritoryChecker::AutoAttackPvPZone(User *pUser)
{
	if(g_ZonePvPAutoAttackRejunte)
	{
		if(pUser->ValidUser())
		{
			time_t now = time(0);
			if(pUser->pSD->nAlive && !pUser->pSD->bHide && pUser->pED->nInCustomAntiRejunteZoneTime < now)
			{
				try
				{
					typedef double (*gdb)(CCreature*, CCreature*, double, int, bool);
					gdb _gdb = (gdb) 0x00513970;


//double __fastcall CCreature::GotDamage(CCreature *this, CCreature *pEnemy, long double dDamage, bool bCanKill, int eDamageType, bool bCanDie)
				//	typedef double (*gdb2)(CCreature*, CCreature*, double, bool, int, bool);
				//	gdb2 _gdb2 = (gdb2) 0x00513330;



					LockPvPZone();
					std::map<UINT, User*> UsersInZonePvPMap2 = UsersInZonePvPMap;
					UnlockPvPZone();

					for(map<UINT, User*>::iterator Iter = UsersInZonePvPMap2.begin();Iter!=UsersInZonePvPMap2.end();Iter++)
					{
						if(User *pUser2 = Iter->second->GetUser())
						{
							if(pUser2->pSD->nAlive && !pUser2->pSD->bHide)
							{
								if(pUser2->pED->nInCustomAntiRejunteZoneTime < now)
								{

								//	CPledge *pPledge1 = pUser->GetPledge() 
								//	CPledge *pPledge2 = pUser->GetPledge() 
									//pUser->GetPledge()->pSD->nDBID

									if (pUser->GetPledge() != pUser2->GetPledge())
									{
										if(pUser->CheckDistance(pUser2, g_ZonePvPAutoAttackRejunteDist))
										{
											bool clanActivo = false;
											double clanDamage = 0;
											if(CPledge *pPledge1 = pUser->GetPledge())
											{
												if(CPledge *pPledge2 = pUser2->GetPledge())
												{
													pPledge2->pSD->pPledgeEx->m_Lock.Enter();
													clanDamage = pPledge2->pSD->pPledgeEx->ClansPowerData[pPledge1->pSD->nDBID];
													pPledge2->pSD->pPledgeEx->m_Lock.Leave();

													if(clanDamage < g_ZonePvPAutoAttackRejunteMinimo)
													{
														_gdb(pUser2->CastCreature(), pUser->CastCreature(), g_ZonePvPAutoAttackRejunteDamage, 6, 1);
													}
													else
													{
														pPledge2->pSD->pPledgeEx->m_Lock.Enter();
														if(pPledge2->pSD->pPledgeEx->ClansPowerData[pPledge1->pSD->nDBID] > g_ZonePvPAutoAttackRejunteResta)
														{
															pPledge2->pSD->pPledgeEx->ClansPowerData[pPledge1->pSD->nDBID] -= g_ZonePvPAutoAttackRejunteResta;
														}
														pPledge2->pSD->pPledgeEx->m_Lock.Leave();
													}
													clanActivo = true;
												}
											}

											if(!clanActivo)
											{
									//			_gdb(pUser2->CastCreature(), pUser->CastCreature(), g_ZonePvPAutoAttackRejunteDamage, 6, 1);
											}
										}
									}
								}
							}
						}
					}
				}catch(...)
				{
					EXCEPTION_LOG;
				}
				
			}
		}
	}
}


void CTerritoryChecker::DelUserPvPZone(User *pUser)
{
	if(g_ZonePvPAutoAttackRejunte)
	{
		if(pUser->ValidUser())
		{
			LockPvPZone();
			try
			{
				map<UINT, User*>::iterator it = UsersInZonePvPMap.find(pUser->nDBID);
				if(it != UsersInZonePvPMap.end())
				{
					UsersInZonePvPMap.erase(it);
				}
			}catch(...)
			{
				g_Log.Add(CLog::Error, "[%s] Exception Detected!", __FUNCTION__);
			}
			UnlockPvPZone();
		}
	}
}




// Función para actualizar la cantidad de personas para un clan en la zona
void CTerritoryChecker::Die(User* pUser) {

	if(pUser->pED->nInCustomEventClanZone)
	{
		CPledge *pPledge = pUser->GetPledge();
		if(pPledge && pPledge->pSD)
		{
			if(ClanIdMaxCounts == pPledge->pSD->nDBID)
			{
				pUser->pED->m_TimeResTeleport = time(0) + 60;
			}

			updateClanUserCount(pPledge->pSD->nDBID, -1);
		}
	}
}


// Función para actualizar la cantidad de personas para un clan en la zona
void CTerritoryChecker::Res(User* pUser) {

	if(pUser->pED->nInCustomEventClanZone)
	{
		CPledge *pPledge = pUser->GetPledge();
		if(pPledge && pPledge->pSD)
		{
			updateClanUserCount(pPledge->pSD->nDBID, 1);
		}
	}
}



// Función para obtener el clan con la mayor cantidad de personas en la zona
int CTerritoryChecker::getClanWithMaxUsers() {
    int maxClanId = -1;
    int maxUserCount = -1;

	Lock();

    for (std::map<int, int>::iterator it = clanUserCountsMap.begin(); it != clanUserCountsMap.end(); ++it) {
        int clanId = it->first;
        int userCount = it->second;

        if (userCount > maxUserCount) {
            maxUserCount = userCount;
            maxClanId = clanId;
        }
    }

	Unlock();

    return maxClanId;
}

int CTerritoryChecker::getClanUserCount(int clanId) {
    Lock();
    int userCount = 0;
    std::map<int, int>::iterator it = clanUserCountsMap.find(clanId);
    if (it != clanUserCountsMap.end()) {
        userCount = it->second;
    }
    Unlock();
    return userCount;
}

void CTerritoryChecker::setClanUserCountTittle(User* pUser) {

	if(pUser->pED->nInCustomEventClanZone)
	{
		CPledge *pPledge = pUser->GetPledge();
		if(pPledge && pPledge->pSD)
		{
			Lock();
			std::map<int, int>::iterator it = clanUserCountsMap.find(pPledge->pSD->nDBID);
			if (it != clanUserCountsMap.end()) {
				std::wstringstream wss;
				wss << pPledge->pSD->wszClanName <<":" << " [ " << it->second << " ]";
				wstring value = wss.str();
				const WCHAR * value2 = value.c_str();
				wcscpy(pUser->wTitle, value2);

				pUser->SetUserInfoChanged();
				pUser->SetCharInfoChanged();
			}
			Unlock();
		}
	}
}

void CTerritoryChecker::ReadData(std::string sFile)
{
	try
	{

		ClanIdMaxCounts = 0;
		clanUserCountsMap.clear();

		ifstream file(sFile.c_str());
		if(file)
		{
			string sLine;
			try
			{
				if(mData.size() > 0)
				{
			/*		for(map<int, CTerritoryEx*>::iterator Iter = mData.begin();Iter!=mData.end();Iter++)
					{
						if(Iter->second)
							delete Iter->second;
						Iter->second = NULL;
					}*/
					mData.clear();
				}
			}catch(...)
			{
				EXCEPTION_LOG;
			}
			INT32 ID = 0;
			while(getline(file, sLine))
			{
				//ParseData
				if(sLine.find("begin") == 0)
				{
					//read base data
					ID++;
					if(sLine.find("begin_ex") == 0)
					{
						vector<FVector> vPoints;
						double z[2] = {0, 0};
						double zRange[2] = {0, 0};
						//begin_ex	Points={{46519;185624;-3550;-3540};{45893;186328;-3570;-3560};{45323;186305;-3580;-3570};{44754;184903;-3520;-3510};{44783;183980;-3530;-3510};{45427;181958;-3490;-3470};{46216;181782;-3490;-3480};{47796;182653;-3510;-3500};{48153;184005;-3550;-3540};{47604;184686;-3550;-3540};{47623;185092;-3510;-3500};{47198;185330;-3500;-3490};{46973;184349;-3560;-3550}}	Type=MINING_ZONE	MiningDataId=1	end_ex
						string points = Parser::ParseOptionString(sLine, "Points");
						points = Parser::Replace(points, '{', ' ');
						points = Parser::Replace(points, '}', ' ');
						points = Parser::Replace(points, ';', ' ');
						bool first = true;
						FVector pos;
						stringstream paramStream;
						paramStream << points;
						while(paramStream >> pos.x >> pos.y >> z[0] >> z[1])
						{
							pos.z = (z[0] + z[1]) / 2;
							vPoints.push_back(pos);
							if(first)
							{
								if(z[0] < z[1])
								{
									zRange[0] = z[0];
									zRange[1] = z[1];
								}else
								{
									zRange[1] = z[0];
									zRange[0] = z[0];
								}
							}else
							{
								if(z[0] < z[1])
								{
									if(zRange[0] > z[0])
									{
										zRange[0] = z[0];
									}
									if(zRange[1] < z[1])
									{
										zRange[1] = z[1];
									}
								}else
								{
									if(zRange[0] > z[1])
									{
										zRange[0] = z[1];
									}
									if(zRange[1] < z[0])
									{
										zRange[1] = z[0];
									}
								}
							}
							

						}

						string sType = Parser::ParseOptionString(sLine, "Type");

						if(sType == "GET_OFF_WYVERN")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(FORBIDDEN_FLY_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_SUMMONING_PC")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(FORBIDDEN_RECALL_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NOBLESS_ZONE")
						{
							CNoblessTerritory *pTerritory = new CNoblessTerritory();
							pTerritory->SetType(NOBLESS_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								IVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_RIDE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(FORBIDDEN_RIDE_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "GLUDIO_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(GLUDIO_CASTLE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "DION_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(DION_CASTLE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "GIRAN_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(GIRAN_CASTLE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "OREN_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(OREN_CASTLE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "ADEN_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(ADEN_CASTLE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "INNADRIL_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(INNADRIL_CASTLE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "GODDARD_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(GODDARD_CASTLE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "RUNE_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(RUNE_CASTLE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "SCHUTTGARD_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(SCHUTTGARD_CASTLE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_OFFLINE_SHOP")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(FORBIDDEN_OFFLINE_SHOP_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_TRADE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(FORBIDDEN_TRADE_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_VOTE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(FORBIDDEN_VOTE_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "TRADE_GEODATA_CHECK")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(TRADE_GEODATA_CHECK_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "SSQ_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(SSQ_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "PRESERVE_ABNORMAL_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(PRESERVE_ABNORMAL_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "PVP_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(PVP_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "ZONE_ANTI_REJUNTE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(ZONE_ANTI_REJUNTE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "PVP_ZONE_STEAL")
						{
							CPvPZoneStealTerritory *pTerritory = new CPvPZoneStealTerritory();
							pTerritory->SetType(PVP_ZONE_STEAL);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							pTerritory->SetRewardId(CParser::GetValueInt(sLine, "RewardId"));
							pTerritory->SetRewardCount(CParser::GetValueInt(sLine, "RewardCount"));
							pTerritory->SetRequiredLevel(CParser::GetValueInt(sLine, "RequiredLevel"));
							pTerritory->SetporPorcentaje(CParser::GetValueInt(sLine, "Porcentaje"));
							pTerritory->SetSpoiler(CParser::GetValueInt(sLine, "IsSpoiler"));

							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "FACTION_ZONE")
						{
							CFactionZoneTerritory *pTerritory = new CFactionZoneTerritory();
							pTerritory->SetType(FACTION_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								IVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}
							string loc2 = Parser::ParseOptionString(sLine, "RedTeamPos");
							if(loc2.size() > 0)
							{
								loc2 = Parser::Replace(loc2, '/', ' ');
								stringstream locStream2(loc2);
								IVector pos2;
								if(locStream2 >> pos2.x >> pos2.y >> pos2.z)
								{
									pTerritory->SetRedTeamPos(pos2.x, pos2.y, pos2.z);
								}
							}
							string loc2_2 = Parser::ParseOptionString(sLine, "RedTeamPos2");
							if(loc2_2.size() > 0)
							{
								loc2_2 = Parser::Replace(loc2_2, '/', ' ');
								stringstream locStream2_2(loc2_2);
								IVector pos2_2;
								if(locStream2_2 >> pos2_2.x >> pos2_2.y >> pos2_2.z)
								{
									pTerritory->SetRedTeamPos2(pos2_2.x, pos2_2.y, pos2_2.z);
								}
							}
							string loc2_3 = Parser::ParseOptionString(sLine, "RedTeamPos3");
							if(loc2_3.size() > 0)
							{
								loc2_3 = Parser::Replace(loc2, '/', ' ');
								stringstream locStream2_3(loc2_3);
								IVector pos2_3;
								if(locStream2_3 >> pos2_3.x >> pos2_3.y >> pos2_3.z)
								{
									pTerritory->SetRedTeamPos3(pos2_3.x, pos2_3.y, pos2_3.z);
								}
							}
							string loc2_4 = Parser::ParseOptionString(sLine, "RedTeamPos4");
							if(loc2_4.size() > 0)
							{
								loc2_4 = Parser::Replace(loc2_4, '/', ' ');
								stringstream locStream2_4(loc2_4);
								IVector pos2_4;
								if(locStream2_4 >> pos2_4.x >> pos2_4.y >> pos2_4.z)
								{
									pTerritory->SetRedTeamPos4(pos2_4.x, pos2_4.y, pos2_4.z);
								}
							}
							string loc3 = Parser::ParseOptionString(sLine, "GreenTeamPos");
							if(loc3.size() > 0)
							{
								loc3 = Parser::Replace(loc3, '/', ' ');
								stringstream locStream3(loc3);
								IVector pos3;
								if(locStream3 >> pos3.x >> pos3.y >> pos3.z)
								{
									pTerritory->SetGreenTeamPos(pos3.x, pos3.y, pos3.z);
								}
							}
							string loc3_2 = Parser::ParseOptionString(sLine, "GreenTeamPos2");
							if(loc3_2.size() > 0)
							{
								loc3_2 = Parser::Replace(loc3_2, '/', ' ');
								stringstream locStream3_2(loc3_2);
								IVector pos3_2;
								if(locStream3_2 >> pos3_2.x >> pos3_2.y >> pos3_2.z)
								{
									pTerritory->SetGreenTeamPos2(pos3_2.x, pos3_2.y, pos3_2.z);
								}
							}
							string loc3_3 = Parser::ParseOptionString(sLine, "GreenTeamPos3");
							if(loc3_3.size() > 0)
							{
								loc3_3 = Parser::Replace(loc3_3, '/', ' ');
								stringstream locStream3_3(loc3_3);
								IVector pos3_3;
								if(locStream3_3 >> pos3_3.x >> pos3_3.y >> pos3_3.z)
								{
									pTerritory->SetGreenTeamPos3(pos3_3.x, pos3_3.y, pos3_3.z);
								}
							}
							string loc3_4 = Parser::ParseOptionString(sLine, "GreenTeamPos4");
							if(loc3_4.size() > 0)
							{
								loc3_4 = Parser::Replace(loc3_4, '/', ' ');
								stringstream locStream3_4(loc3_4);
								IVector pos3_4;
								if(locStream3_4 >> pos3_4.x >> pos3_4.y >> pos3_4.z)
								{
									pTerritory->SetGreenTeamPos4(pos3_4.x, pos3_4.y, pos3_4.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "DAILY_PVP")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(DAILY_PVP);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}
						else if(sType == "BUFF_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(BUFF_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "SHOW_HP_TITLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(SHOW_HP_TITLE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NO_DROP_ITEM_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(NO_DROP_ITEM_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NOCHARSHOWZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(NOCHARSHOWZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NOPKZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(NOPKZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "EVENT_PENALTY_CLAN_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(EVENT_PENALTY_CLAN_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NO_TRADE_ITEM_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(NO_TRADE_ITEM_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NO_BUY_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(NO_BUY_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NO_SELL_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(NO_SELL_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NO_CRAFT_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(NO_CRAFT_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "JAIL_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(JAIL_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "DISPEL_ALL_ZONE")
						{
							CDispelAllTerritory *pTerritory = new CDispelAllTerritory();
							pTerritory->SetType(DISPEL_ALL_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							BOOL onEnter = CParser::GetValueInt(sLine, "OnEnterOnly");
							pTerritory->SetOnEnterOnly(onEnter);
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NO_PARTY_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(NO_PARTY_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "ANTI_RECALL_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(ANTI_RECALL_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_SCHEME_BUFFER_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(BLOCK_SCHEME_BUFFER_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NICKNAME_CHANGE_ZONE")
						{
							CNickNameChangeTerritory *pTerritory = new CNickNameChangeTerritory();
							pTerritory->SetType(NICKNAME_CHANGE_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							string sName = CParser::GetValueString(sLine, "NickName");
							DWORD Color = CParser::GetValueInt(sLine, "Color");
							DWORD HidePledge = CParser::GetValueInt(sLine, "HidePledge");
							wchar_t wName[512]; memset(wName, 0, sizeof(wName));
							_AnsiToUnicode(sName.c_str(), wName);
							pTerritory->SetNickName(wName);
							pTerritory->SetColor(Color);
							pTerritory->SetHidePledge(HidePledge);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_ITEMS_ZONE")
						{
							CBlockItemsTerritory *pTerritory = new CBlockItemsTerritory();
							pTerritory->SetType(BLOCK_ITEMS_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							string sItemList = CParser::GetValueString(sLine, "ItemList");
							sItemList = CParser::Replace(sItemList, ';', ' ');
							stringstream sstr;
							sstr << sItemList;
							int ItemID = 0;
							while(sstr >> ItemID)
							{
								pTerritory->AddItem(ItemID);
								ItemID = 0;
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "EVENT_PVP_ZONE")
						{
							CEventPvPTerritory *pTerritory = new CEventPvPTerritory();
							pTerritory->SetType(EVENT_PVP_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);

							int lev = Parser::ParseOptionInt(sLine, "MinLevel", 0);
							pTerritory->SetMinLevel(lev);

							int level = Parser::ParseOptionInt(sLine, "MaxLevel", 100);
							pTerritory->SetMaxLevel(level);

							int enchant = Parser::ParseOptionInt(sLine, "MaxEnchant", 65535);
							pTerritory->SetMaxEnchant(enchant);

							string sClase = CParser::GetValueString(sLine, "Clase");
							wstring wClase = StringToWString(sClase);
							if(!wcscmp(wClase.c_str(), L"ALL"))
								 pTerritory->SetClase(999);
							else if(!wcscmp(wClase.c_str(), L"WARRIOR"))
								pTerritory->SetClase(1);
							else if(!wcscmp(wClase.c_str(), L"MAGO"))
								pTerritory->SetClase(2);
							else 
								pTerritory->SetClase(999);

							string sGradeList = CParser::GetValueString(sLine, "GradeList");
							sGradeList = CParser::Replace(sGradeList, ';', ' ');
							stringstream sstr;
							sstr << sGradeList;
							string Grade = "";
							int GradeID = 0;
							while(sstr >> Grade)
							{
								wstring wGrade = StringToWString(Grade);
								if(!wcscmp(wGrade.c_str(), L"NONE"))
									GradeID = 0;
								else if(!wcscmp(wGrade.c_str(), L"D"))
									GradeID = 1;
								else if(!wcscmp(wGrade.c_str(), L"C"))
									GradeID = 2;
								else if(!wcscmp(wGrade.c_str(), L"B"))
									GradeID = 3;
								else if(!wcscmp(wGrade.c_str(), L"A"))
									GradeID = 4;
								else if(!wcscmp(wGrade.c_str(), L"S"))
									GradeID = 5;
								else 
									GradeID = 0;


								pTerritory->AddGrade(GradeID);
								GradeID = 0;
							}

							string sItemList = CParser::GetValueString(sLine, "ItemList");
							sItemList = CParser::Replace(sItemList, ';', ' ');
							stringstream sstr2;
							sstr2 << sItemList;
							int ItemID = 0;
							while(sstr2 >> ItemID)
							{
								pTerritory->AddItem(ItemID);
								ItemID = 0;
							}

							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos);
								}
							}

							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_SKILLS_ZONE")
						{
							CBlockSkillsTerritory *pTerritory = new CBlockSkillsTerritory();
							pTerritory->SetType(BLOCK_SKILLS_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							string sSkillList = CParser::GetValueString(sLine, "SkillList");
							sSkillList = CParser::Replace(sSkillList, ';', ' ');
							stringstream sstr;
							sstr << sSkillList;
							int SkillID = 0;
							while(sstr >> SkillID)
							{
								pTerritory->AddSkill(SkillID);
								SkillID = 0;
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "LEVEL_RESTRICTION_ZONE")
						{
							CLevelRestrictionTerritory *pTerritory = new CLevelRestrictionTerritory();
							pTerritory->SetType(LEVEL_RESTRICTION_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							int level = Parser::ParseOptionInt(sLine, "MinLevel", 0);
							pTerritory->SetMinLevel(level);
							level = Parser::ParseOptionInt(sLine, "MaxLevel", 80);
							pTerritory->SetMaxLevel(level);
							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "HWID_LIMIT_ZONE")
						{
							CHwidLimitTerritory *pTerritory = new CHwidLimitTerritory();
							pTerritory->SetType(HWID_LIMIT_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							int level = Parser::ParseOptionInt(sLine, "MinLevel", 0);
							pTerritory->SetMinLevel(level);
							level = Parser::ParseOptionInt(sLine, "MaxLevel", 80);
							pTerritory->SetMaxLevel(level);
							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos);
								}
							}

							pTerritory->SetCheckingHWID(CParser::GetValueInt(sLine, "CheckHWID"));

							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "RESPAWN_ZONE")
						{
							CRespawnTerritory *pTerritory = new CRespawnTerritory();
							pTerritory->SetType(RESPAWN_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							
							//begin_ex	Type=RESPAWN_ZONE	HpRatio=100	CpRatio=100	MpRatio=100	ProtectBuffs=1	RespawnPos={{46519;185624;-3550;-3540};{45893;186328;-3570;-3560};{45323;186305;-3580;-3570}}	Points={{46519;185624;-3550;-3540};{45893;186328;-3570;-3560};{45323;186305;-3580;-3570};{44754;184903;-3520;-3510};{44783;183980;-3530;-3510};{45427;181958;-3490;-3470};{46216;181782;-3490;-3480};{47796;182653;-3510;-3500};{48153;184005;-3550;-3540};{47604;184686;-3550;-3540};{47623;185092;-3510;-3500};{47198;185330;-3500;-3490};{46973;184349;-3560;-3550}} end_ex
							int hpRatio = Parser::ParseOptionInt(sLine, "HpRatio");
							int cpRatio = Parser::ParseOptionInt(sLine, "CpRatio");
							int mpRatio = Parser::ParseOptionInt(sLine, "MpRatio");
							bool protectBuffs = Parser::ParseOptionInt(sLine, "ProtectBuffs", 0) ? true : false;
							pTerritory->SetHpRatio(hpRatio);
							pTerritory->SetMpRatio(mpRatio);
							pTerritory->SetCpRatio(cpRatio);
							pTerritory->SetProtectBuffs(protectBuffs);

							string respawn = Parser::ParseOptionString(sLine, "RespawnPos");
							respawn = Parser::Replace(respawn, ';', ' ');
							respawn = Parser::Replace(respawn, '{', ' ');
							respawn = Parser::Replace(respawn, '}', ' ');
							stringstream respawnStream(respawn);
							IVector pos;
							while(respawnStream >> pos.x >> pos.y >> pos.z)
							{
								pTerritory->AddRespawn(pos.x, pos.y, pos.z);
								pos.x = pos.y = pos.z = 0;
							}
							
							mData[ID] = pTerritory;
						}else if(sType == "REQUIRED_ITEM_ZONE")
						{
							CRequiredItemTerritory *pTerritory = new CRequiredItemTerritory();
							pTerritory->SetType(REQUIRED_ITEM_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							string itemList = CParser::GetValueString(sLine, "ItemList");
							itemList = CParser::Replace(itemList, ';', ' ');
							itemList = CParser::Replace(itemList, '{', ' ');
							itemList = CParser::Replace(itemList, '}', ' ');
							stringstream sstr;
							sstr << itemList;
							int itemId = 0;
							while(sstr >> itemId)
							{
								pTerritory->AddItem(itemId);
								itemId = 0;
							}
							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								IVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "INSTANCE_ZONE")
						{
							CInstanceTerritory *pTerritory = new CInstanceTerritory();
							pTerritory->SetType(INSTANCE_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							pTerritory->SetInstanceId(Parser::ParseOptionInt(sLine, "InstanceId"));
							pTerritory->SetAllowedTime(Parser::ParseOptionInt(sLine, "AllowedTime"));
							pTerritory->SetReuseTime(Parser::ParseOptionInt(sLine, "ReuseTime"));
							pTerritory->SetByHWID(Parser::ParseOptionInt(sLine, "LockHwid"));

							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								loc = Parser::Replace(loc, '\\', ' ');
								loc = Parser::Replace(loc, ',', ' ');
								stringstream locStream(loc);
								IVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NO_RESTART_ZONE")
						{
							CNoRestartTerritory *pTerritory = new CNoRestartTerritory();
							pTerritory->SetType(NO_RESTART_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								IVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutLocation(pos.x, pos.y, pos.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "PARTY_ZONE")
						{
							CPartyTerritory *pTerritory = new CPartyTerritory();
							pTerritory->SetType(PARTY_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							int members = Parser::ParseOptionInt(sLine, "MinMembers", 2);
							pTerritory->SetMinMembers(members);
							members = Parser::ParseOptionInt(sLine, "MaxMembers", 9);
							pTerritory->SetMaxMembers(members);
							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "RACE_CHANGE_ZONE")
						{
							CRaceChangeTerritory *pTerritory = new CRaceChangeTerritory();
							pTerritory->SetType(RACE_CHANGE_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							INT32 Race = CParser::GetValueInt(sLine, "Race");
							INT32 Sex = CParser::GetValueInt(sLine, "Sex");
							pTerritory->SetData(Race >= 0 ? Race : UINT_MAX, Sex >= 0 ? Sex : UINT_MAX);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}
						else if(sType == "BLOCK_APPEARENCE_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(BLOCK_APPEARENCE_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}
						else if(sType == "NO_OL_BUFFS_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(NO_OL_BUFFS_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_CHAT_ZONE")
						{
							CBlockChatTerritory *pTerritory = new CBlockChatTerritory();
							pTerritory->SetType(BLOCK_CHAT_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							pTerritory->SetData(CParser::GetValueInt(sLine, "All"), CBlockChatTerritory::ALL);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Shout"), CBlockChatTerritory::SHOUT);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Tell"), CBlockChatTerritory::TELL);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Party"), CBlockChatTerritory::PARTY);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Clan"), CBlockChatTerritory::CLAN);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Trade"), CBlockChatTerritory::TRADE);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Alliance"), CBlockChatTerritory::ALLIANCE);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Hero"), CBlockChatTerritory::HERO);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Msn"), CBlockChatTerritory::MSN);
							
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_TVT_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(BLOCK_TVT_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_ALL_SKILLS_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->SetType(BLOCK_ALL_SKILLS_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "PVP_REWARD_ZONE")
						{
							CPvPRewardTerritory *pTerritory = new CPvPRewardTerritory();
							pTerritory->SetType(PVP_REWARD_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							pTerritory->SetRewardId(CParser::GetValueInt(sLine, "RewardId"));
							pTerritory->SetRewardCount(CParser::GetValueInt(sLine, "RewardCount"));
							pTerritory->SetRequiredLevel(CParser::GetValueInt(sLine, "RequiredLevel"));
							pTerritory->SetStealFromVictim(CParser::GetValueInt(sLine, "StealFromVictim"));
							pTerritory->SetCheckingHWID(CParser::GetValueInt(sLine, "CheckHWID"));
							pTerritory->SetKillReuse(CParser::GetValueInt(sLine, "KillReuse"));
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "WAR_REWARD_ZONE")
						{
							CWarRewardTerritory *pTerritory = new CWarRewardTerritory();
							pTerritory->SetType(WAR_REWARD_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							pTerritory->SetRewardId(CParser::GetValueInt(sLine, "RewardId"));
							pTerritory->SetRewardCount(CParser::GetValueInt(sLine, "RewardCount"));
							pTerritory->SetRequiredLevel(CParser::GetValueInt(sLine, "RequiredLevel"));
							pTerritory->SetStealFromVictim(CParser::GetValueInt(sLine, "StealFromVictim"));
							pTerritory->SetCheckingHWID(CParser::GetValueInt(sLine, "CheckHWID"));
							pTerritory->SetKillReuse(CParser::GetValueInt(sLine, "KillReuse"));
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "PK_REWARD_ZONE")
						{
							CPkRewardTerritory *pTerritory = new CPkRewardTerritory();
							pTerritory->SetType(PK_REWARD_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							pTerritory->SetRewardId(CParser::GetValueInt(sLine, "RewardId"));
							pTerritory->SetRewardCount(CParser::GetValueInt(sLine, "RewardCount"));
							pTerritory->SetRequiredLevel(CParser::GetValueInt(sLine, "RequiredLevel"));
							pTerritory->SetStealFromVictim(CParser::GetValueInt(sLine, "StealFromVictim"));
							pTerritory->SetCheckingHWID(CParser::GetValueInt(sLine, "CheckHWID"));
							pTerritory->SetKillReuse(CParser::GetValueInt(sLine, "KillReuse"));
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NOPKZONE")
						{
							CNoPKZoneTerritory *pTerritory = new CNoPKZoneTerritory();
							pTerritory->SetType(NOPKZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							pTerritory->SetPenaltyTime(CParser::GetValueInt(sLine, "penaltyTime"));
							pTerritory->SetRequiredLevel(CParser::GetValueInt(sLine, "RequiredLevel"));

							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}

							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "EVENT_PENALTY_CLAN_ZONE")
						{
							CNoPKZoneTerritory *pTerritory = new CNoPKZoneTerritory();
							pTerritory->SetType(EVENT_PENALTY_CLAN_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							pTerritory->SetPenaltyTime(CParser::GetValueInt(sLine, "penaltyTime"));
							pTerritory->SetRequiredLevel(CParser::GetValueInt(sLine, "RequiredLevel"));

							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}

							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "DESPAWN_SUMMON_ZONE")
						{
							CDespawnSummonTerritory *pTerritory = new CDespawnSummonTerritory();
							pTerritory->SetType(DESPAWN_SUMMON_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							string sSkillList = Parser::ParseOptionString(sLine, "SummonList");
							sSkillList = CParser::Replace(sSkillList, ';', ' ');
							stringstream sstr;
							sstr << sSkillList;
							INT32 classId = 0;
							while(sstr >> classId)
							{
								pTerritory->Block(classId);
								classId = 0;
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "DISPEL_SKILL_ZONE")
						{
							CDispelSkillTerritory *pTerritory = new CDispelSkillTerritory();
							pTerritory->SetType(DISPEL_SKILL_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							string sSkillList = Parser::ParseOptionString(sLine, "SkillList");
							sSkillList = CParser::Replace(sSkillList, ';', ' ');
							stringstream sstr;
							sstr << sSkillList;
							string skillName;
							while(sstr >> skillName)
							{
								wstring wName = StringToWString(skillName);
								INT32 skillId = 0;
								INT32 level = 0;
								g_SkillDB.GetSkillIdLevelByName(wName.c_str(), &skillId, &level);
								if(skillId > 0 && level > 0)
								{
									pTerritory->Block(skillId, level);
								}else
								{
									g_Log.Add(CLog::Error, "[%s] Invalid skill name[%s]", __FUNCTION__, skillName.c_str());
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "MINING_ZONE")
						{
							CMiningTerritory *pTerritory = new CMiningTerritory();
							pTerritory->SetType(MINING_ZONE);
							for(INT32 n=0;n<vPoints.size();n++)
							{
								pTerritory->AddPoint(vPoints[n]);
							}
							pTerritory->AddZRange(zRange[0], zRange[1]);
							pTerritory->SetMiningId(Parser::ParseOptionInt(sLine, "MiningDataId"));
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else
						{
							g_Log.Add(CLog::Error, "[%s] Unknown Type[%s] territory_id[%d]", __FUNCTION__, sType.c_str(), ID);
						}
					}
					else
					{
						double x = CParser::GetValueDouble(sLine, "MinX");
						double X = CParser::GetValueDouble(sLine, "MaxX");
						double y = CParser::GetValueDouble(sLine, "MinY");
						double Y = CParser::GetValueDouble(sLine, "MaxY");
						double z = CParser::GetValueDouble(sLine, "MinZ");
						double Z = CParser::GetValueDouble(sLine, "MaxZ");
						string sType = CParser::GetValueString(sLine, "Type");
						if(sType == "GET_OFF_WYVERN")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, FORBIDDEN_FLY_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_SUMMONING_PC")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, FORBIDDEN_RECALL_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NOBLESS_ZONE")
						{
							CNoblessTerritory *pTerritory = new CNoblessTerritory();
							pTerritory->Set(x,X, y, Y, z, Z, NOBLESS_ZONE);
							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								IVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_RIDE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, FORBIDDEN_RIDE_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "GLUDIO_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, GLUDIO_CASTLE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "DION_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, DION_CASTLE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "GIRAN_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, GIRAN_CASTLE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "OREN_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, OREN_CASTLE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "ADEN_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, ADEN_CASTLE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "INNADRIL_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, INNADRIL_CASTLE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "GODDARD_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, GODDARD_CASTLE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "RUNE_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, RUNE_CASTLE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "SCHUTTGARD_CASTLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, SCHUTTGARD_CASTLE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_OFFLINE_SHOP")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, FORBIDDEN_OFFLINE_SHOP_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_TRADE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, FORBIDDEN_TRADE_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_VOTE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, FORBIDDEN_VOTE_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "TRADE_GEODATA_CHECK")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, TRADE_GEODATA_CHECK_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "SSQ_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, SSQ_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "PRESERVE_ABNORMAL_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, PRESERVE_ABNORMAL_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "PVP_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, PVP_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "ZONE_ANTI_REJUNTE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, ZONE_ANTI_REJUNTE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "FACTION_ZONE")
						{
							CFactionZoneTerritory *pTerritory = new CFactionZoneTerritory();
							pTerritory->Set(x,X, y, Y, z, Z, FACTION_ZONE);

							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								IVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}
							string loc2 = Parser::ParseOptionString(sLine, "RedTeamPos");
							if(loc2.size() > 0)
							{
								loc2 = Parser::Replace(loc2, '/', ' ');
								stringstream locStream2(loc2);
								IVector pos2;
								if(locStream2 >> pos2.x >> pos2.y >> pos2.z)
								{
									pTerritory->SetRedTeamPos(pos2.x, pos2.y, pos2.z);
								}
							}
							string loc2_2 = Parser::ParseOptionString(sLine, "RedTeamPos2");
							if(loc2_2.size() > 0)
							{
								loc2_2 = Parser::Replace(loc2_2, '/', ' ');
								stringstream locStream2_2(loc2_2);
								IVector pos2_2;
								if(locStream2_2 >> pos2_2.x >> pos2_2.y >> pos2_2.z)
								{
									pTerritory->SetRedTeamPos2(pos2_2.x, pos2_2.y, pos2_2.z);
								}
							}
							string loc2_3 = Parser::ParseOptionString(sLine, "RedTeamPos3");
							if(loc2_3.size() > 0)
							{
								loc2_3 = Parser::Replace(loc2, '/', ' ');
								stringstream locStream2_3(loc2_3);
								IVector pos2_3;
								if(locStream2_3 >> pos2_3.x >> pos2_3.y >> pos2_3.z)
								{
									pTerritory->SetRedTeamPos3(pos2_3.x, pos2_3.y, pos2_3.z);
								}
							}
							string loc2_4 = Parser::ParseOptionString(sLine, "RedTeamPos4");
							if(loc2_4.size() > 0)
							{
								loc2_4 = Parser::Replace(loc2_4, '/', ' ');
								stringstream locStream2_4(loc2_4);
								IVector pos2_4;
								if(locStream2_4 >> pos2_4.x >> pos2_4.y >> pos2_4.z)
								{
									pTerritory->SetRedTeamPos4(pos2_4.x, pos2_4.y, pos2_4.z);
								}
							}
							string loc3 = Parser::ParseOptionString(sLine, "GreenTeamPos");
							if(loc3.size() > 0)
							{
								loc3 = Parser::Replace(loc3, '/', ' ');
								stringstream locStream3(loc3);
								IVector pos3;
								if(locStream3 >> pos3.x >> pos3.y >> pos3.z)
								{
									pTerritory->SetGreenTeamPos(pos3.x, pos3.y, pos3.z);
								}
							}
							string loc3_2 = Parser::ParseOptionString(sLine, "GreenTeamPos2");
							if(loc3_2.size() > 0)
							{
								loc3_2 = Parser::Replace(loc3_2, '/', ' ');
								stringstream locStream3_2(loc3_2);
								IVector pos3_2;
								if(locStream3_2 >> pos3_2.x >> pos3_2.y >> pos3_2.z)
								{
									pTerritory->SetGreenTeamPos2(pos3_2.x, pos3_2.y, pos3_2.z);
								}
							}
							string loc3_3 = Parser::ParseOptionString(sLine, "GreenTeamPos3");
							if(loc3_3.size() > 0)
							{
								loc3_3 = Parser::Replace(loc3_3, '/', ' ');
								stringstream locStream3_3(loc3_3);
								IVector pos3_3;
								if(locStream3_3 >> pos3_3.x >> pos3_3.y >> pos3_3.z)
								{
									pTerritory->SetGreenTeamPos3(pos3_3.x, pos3_3.y, pos3_3.z);
								}
							}
							string loc3_4 = Parser::ParseOptionString(sLine, "GreenTeamPos4");
							if(loc3_4.size() > 0)
							{
								loc3_4 = Parser::Replace(loc3_4, '/', ' ');
								stringstream locStream3_4(loc3_4);
								IVector pos3_4;
								if(locStream3_4 >> pos3_4.x >> pos3_4.y >> pos3_4.z)
								{
									pTerritory->SetGreenTeamPos4(pos3_4.x, pos3_4.y, pos3_4.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "DAILY_PVP")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x, X, y, Y, z, Z, DAILY_PVP);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BUFF_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x, X, y, Y, z, Z, BUFF_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "SHOW_HP_TITLE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x, X, y, Y, z, Z, SHOW_HP_TITLE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NO_DROP_ITEM_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x, X, y, Y, z, Z, NO_DROP_ITEM_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NOCHARSHOWZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x, X, y, Y, z, Z, NOCHARSHOWZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}
						else if(sType == "NO_TRADE_ITEM_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x, X, y, Y, z, Z, NO_TRADE_ITEM_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NO_BUY_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x, X, y, Y, z, Z, NO_BUY_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NO_SELL_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x, X, y, Y, z, Z, NO_SELL_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NO_CRAFT_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x, X, y, Y, z, Z, NO_CRAFT_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_ALL_SKILLS_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x, X, y, Y, z, Z, BLOCK_ALL_SKILLS_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "JAIL_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x, X, y, Y, z, Z, JAIL_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "DISPEL_ALL_ZONE")
						{
							CDispelAllTerritory *pTerritory = new CDispelAllTerritory();
							pTerritory->Set(x,X, y, Y, z, Z, DISPEL_ALL_ZONE);
							BOOL onEnter = CParser::GetValueInt(sLine, "OnEnterOnly");
							pTerritory->SetOnEnterOnly(onEnter);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NO_PARTY_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, NO_PARTY_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "ANTI_RECALL_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, ANTI_RECALL_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_SCHEME_BUFFER_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, BLOCK_SCHEME_BUFFER_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NICKNAME_CHANGE_ZONE")
						{
							CNickNameChangeTerritory *pTerritory = new CNickNameChangeTerritory();
							pTerritory->Set(x,X, y, Y, z, Z, NICKNAME_CHANGE_ZONE);
							string sName = CParser::GetValueString(sLine, "NickName");
							DWORD Color = CParser::GetValueInt(sLine, "Color");
							DWORD HidePledge = CParser::GetValueInt(sLine, "HidePledge");
							wchar_t wName[512]; memset(wName, 0, sizeof(wName));
							_AnsiToUnicode(sName.c_str(), wName);
							pTerritory->SetNickName(wName);
							pTerritory->SetColor(Color);
							pTerritory->SetHidePledge(HidePledge);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_ITEMS_ZONE")
						{
							CBlockItemsTerritory *pTerritory = new CBlockItemsTerritory();
							pTerritory->Set(x,X, y, Y, z, Z, BLOCK_ITEMS_ZONE);
							string sItemList = CParser::GetValueString(sLine, "ItemList");
							sItemList = CParser::Replace(sItemList, ';', ' ');
							stringstream sstr;
							sstr << sItemList;
							int ItemID = 0;
							while(sstr >> ItemID)
							{
								pTerritory->AddItem(ItemID);
								ItemID = 0;
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "EVENT_PVP_ZONE")
						{
							CEventPvPTerritory *pTerritory = new CEventPvPTerritory();
							pTerritory->Set(x,X, y, Y, z, Z, EVENT_PVP_ZONE);

							int lev = Parser::ParseOptionInt(sLine, "MinLevel", 0);
							pTerritory->SetMinLevel(lev);

							int level = Parser::ParseOptionInt(sLine, "MaxLevel", 100);
							pTerritory->SetMaxLevel(level);

							int enchant = Parser::ParseOptionInt(sLine, "MaxEnchant", 65535);
							pTerritory->SetMaxEnchant(enchant);


							string sClase = CParser::GetValueString(sLine, "Clase");
							wstring wClase = StringToWString(sClase);
							if(!wcscmp(wClase.c_str(), L"ALL"))
								 pTerritory->SetClase(999);
							else if(!wcscmp(wClase.c_str(), L"WARRIOR"))
								pTerritory->SetClase(1);
							else if(!wcscmp(wClase.c_str(), L"MAGO"))
								pTerritory->SetClase(2);
							else 
								pTerritory->SetClase(999);


							string sGradeList = CParser::GetValueString(sLine, "GradeList");
							sGradeList = CParser::Replace(sGradeList, ';', ' ');
							stringstream sstr;
							sstr << sGradeList;
							string Grade = "";
							int GradeID = 0;
							while(sstr >> Grade)
							{
								wstring wGrade = StringToWString(Grade);
								if(!wcscmp(wGrade.c_str(), L"NONE"))
									GradeID = 0;
								else if(!wcscmp(wGrade.c_str(), L"D"))
									GradeID = 1;
								else if(!wcscmp(wGrade.c_str(), L"C"))
									GradeID = 2;
								else if(!wcscmp(wGrade.c_str(), L"B"))
									GradeID = 3;
								else if(!wcscmp(wGrade.c_str(), L"A"))
									GradeID = 4;
								else if(!wcscmp(wGrade.c_str(), L"S"))
									GradeID = 5;
								else 
									GradeID = 0;

								pTerritory->AddGrade(GradeID);
								GradeID = 0;
							}

							string sItemList = CParser::GetValueString(sLine, "ItemList");
							sItemList = CParser::Replace(sItemList, ';', ' ');
							stringstream sstr2;
							sstr2 << sItemList;
							int ItemID = 0;
							while(sstr2 >> ItemID)
							{
								pTerritory->AddItem(ItemID);
								ItemID = 0;
							}

							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos);
								}
							}

							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "PVP_ZONE_STEAL")
						{
							CPvPZoneStealTerritory *pTerritory = new CPvPZoneStealTerritory();
							pTerritory->Set(x,X, y, Y, z, Z, PVP_ZONE_STEAL);
							pTerritory->SetRewardId(CParser::GetValueInt(sLine, "RewardId"));
							pTerritory->SetRewardCount(CParser::GetValueInt(sLine, "RewardCount"));
							pTerritory->SetRequiredLevel(CParser::GetValueInt(sLine, "RequiredLevel"));
							pTerritory->SetporPorcentaje(CParser::GetValueInt(sLine, "Porcentaje"));
							pTerritory->SetSpoiler(CParser::GetValueInt(sLine, "IsSpoiler"));

							

							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_SKILLS_ZONE")
						{
							CBlockSkillsTerritory *pTerritory = new CBlockSkillsTerritory();
							pTerritory->Set(x,X, y, Y, z, Z, BLOCK_SKILLS_ZONE);
							string sSkillList = CParser::GetValueString(sLine, "SkillList");
							sSkillList = CParser::Replace(sSkillList, ';', ' ');
							stringstream sstr;
							sstr << sSkillList;
							int SkillID = 0;
							while(sstr >> SkillID)
							{
								pTerritory->AddSkill(SkillID);
								SkillID = 0;
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "RACE_CHANGE_ZONE")
						{
							CRaceChangeTerritory *pTerritory = new CRaceChangeTerritory();
							pTerritory->Set(x,X, y, Y, z, Z, RACE_CHANGE_ZONE);
							INT32 Race = CParser::GetValueInt(sLine, "Race");
							INT32 Sex = CParser::GetValueInt(sLine, "Sex");
							pTerritory->SetData(Race >= 0 ? Race : UINT_MAX, Sex >= 0 ? Sex : UINT_MAX);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "LEVEL_RESTRICTION_ZONE")
						{
							CLevelRestrictionTerritory *pTerritory = new CLevelRestrictionTerritory();
							pTerritory->SetType(LEVEL_RESTRICTION_ZONE);
							pTerritory->Set(x,X, y, Y, z, Z, LEVEL_RESTRICTION_ZONE);
							int level = Parser::ParseOptionInt(sLine, "MinLevel", 0);
							pTerritory->SetMinLevel(level);
							level = Parser::ParseOptionInt(sLine, "MaxLevel", 80);
							pTerritory->SetMaxLevel(level);
							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "HWID_LIMIT_ZONE")
						{
							CHwidLimitTerritory *pTerritory = new CHwidLimitTerritory();
							pTerritory->SetType(HWID_LIMIT_ZONE);
							pTerritory->Set(x,X, y, Y, z, Z, HWID_LIMIT_ZONE);
							int level = Parser::ParseOptionInt(sLine, "MinLevel", 0);
							pTerritory->SetMinLevel(level);
							level = Parser::ParseOptionInt(sLine, "MaxLevel", 80);
							pTerritory->SetMaxLevel(level);
							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos);
								}
							}

							pTerritory->SetCheckingHWID(CParser::GetValueInt(sLine, "CheckHWID"));

							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "INSTANCE_ZONE")
						{

							CInstanceTerritory *pTerritory = new CInstanceTerritory();
							pTerritory->SetType(INSTANCE_ZONE);
							pTerritory->Set(x,X, y, Y, z, Z, INSTANCE_ZONE);
							
							pTerritory->SetInstanceId(Parser::ParseOptionInt(sLine, "InstanceId"));
							pTerritory->SetAllowedTime(Parser::ParseOptionInt(sLine, "AllowedTime"));
							pTerritory->SetReuseTime(Parser::ParseOptionInt(sLine, "ReuseTime"));
							pTerritory->SetByHWID(Parser::ParseOptionInt(sLine, "LockHwid"));

							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								loc = Parser::Replace(loc, '\\', ' ');
								loc = Parser::Replace(loc, ',', ' ');
								stringstream locStream(loc);
								IVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "RESPAWN_ZONE")
						{
							CRespawnTerritory *pTerritory = new CRespawnTerritory();
							pTerritory->SetType(RESPAWN_ZONE);
							pTerritory->Set(x,X, y, Y, z, Z, RESPAWN_ZONE);
							
//begin_ex	Type=RESPAWN_ZONE	HpRatio=100	CpRatio=100	MpRatio=100	ProtectBuffs=1	RespawnPos={{46519;185624;-3550;-3540};{45893;186328;-3570;-3560};{45323;186305;-3580;-3570}}	Points={{46519;185624;-3550;-3540};{45893;186328;-3570;-3560};{45323;186305;-3580;-3570};{44754;184903;-3520;-3510};{44783;183980;-3530;-3510};{45427;181958;-3490;-3470};{46216;181782;-3490;-3480};{47796;182653;-3510;-3500};{48153;184005;-3550;-3540};{47604;184686;-3550;-3540};{47623;185092;-3510;-3500};{47198;185330;-3500;-3490};{46973;184349;-3560;-3550}} end_ex
							int hpRatio = Parser::ParseOptionInt(sLine, "HpRatio");
							int cpRatio = Parser::ParseOptionInt(sLine, "CpRatio");
							int mpRatio = Parser::ParseOptionInt(sLine, "MpRatio");
							bool protectBuffs = Parser::ParseOptionInt(sLine, "ProtectBuffs", 0) ? true : false;
							pTerritory->SetHpRatio(hpRatio);
							pTerritory->SetMpRatio(mpRatio);
							pTerritory->SetCpRatio(cpRatio);
							pTerritory->SetProtectBuffs(protectBuffs);

							string respawn = Parser::ParseOptionString(sLine, "RespawnPos");
							respawn = Parser::Replace(respawn, ';', ' ');
							respawn = Parser::Replace(respawn, '{', ' ');
							respawn = Parser::Replace(respawn, '}', ' ');
							stringstream respawnStream(respawn);
							IVector pos;
							while(respawnStream >> pos.x >> pos.y >> pos.z)
							{
								pTerritory->AddRespawn(pos.x, pos.y, pos.z);
								pos.x = pos.y = pos.z = 0;
							}
							
							mData[ID] = pTerritory;
						}else if(sType == "REQUIRED_ITEM_ZONE")
						{
							CRequiredItemTerritory *pTerritory = new CRequiredItemTerritory();
							pTerritory->SetType(REQUIRED_ITEM_ZONE);
							pTerritory->Set(x,X, y, Y, z, Z, REQUIRED_ITEM_ZONE);
							
							string itemList = CParser::GetValueString(sLine, "ItemList");
							itemList = CParser::Replace(itemList, ';', ' ');
							itemList = CParser::Replace(itemList, '{', ' ');
							itemList = CParser::Replace(itemList, '}', ' ');
							stringstream sstr;
							sstr << itemList;
							int itemId = 0;
							while(sstr >> itemId)
							{
								pTerritory->AddItem(itemId);
								itemId = 0;
							}
							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								IVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NO_RESTART_ZONE")
						{
							CNoRestartTerritory *pTerritory = new CNoRestartTerritory();
							pTerritory->SetType(NO_RESTART_ZONE);
							pTerritory->Set(x,X, y, Y, z, Z, NO_RESTART_ZONE);
							
							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								IVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutLocation(pos.x, pos.y, pos.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "PARTY_ZONE")
						{
							CPartyTerritory *pTerritory = new CPartyTerritory();
							pTerritory->SetType(PARTY_ZONE);
							pTerritory->Set(x,X, y, Y, z, Z, PARTY_ZONE);
							int members = Parser::ParseOptionInt(sLine, "MinMembers", 2);
							pTerritory->SetMinMembers(members);
							members = Parser::ParseOptionInt(sLine, "MaxMembers", 9);
							pTerritory->SetMaxMembers(members);
							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}					
						else if(sType == "BLOCK_APPEARENCE_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, BLOCK_APPEARENCE_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}
						else if(sType == "NO_OL_BUFFS_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x,X, y, Y, z, Z, NO_OL_BUFFS_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_CHAT_ZONE")
						{
							CBlockChatTerritory *pTerritory = new CBlockChatTerritory();
							pTerritory->Set(x,X, y, Y, z, Z, BLOCK_CHAT_ZONE);
							pTerritory->SetData(CParser::GetValueInt(sLine, "All"), CBlockChatTerritory::ALL);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Shout"), CBlockChatTerritory::SHOUT);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Tell"), CBlockChatTerritory::TELL);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Party"), CBlockChatTerritory::PARTY);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Clan"), CBlockChatTerritory::CLAN);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Trade"), CBlockChatTerritory::TRADE);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Alliance"), CBlockChatTerritory::ALLIANCE);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Hero"), CBlockChatTerritory::HERO);
							pTerritory->SetData(CParser::GetValueInt(sLine, "Msn"), CBlockChatTerritory::MSN);
							
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "BLOCK_TVT_ZONE")
						{
							CTerritoryEx *pTerritory = new CTerritoryEx();
							pTerritory->Set(x, X, y, Y, z, Z, BLOCK_TVT_ZONE);
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "PVP_REWARD_ZONE")
						{
							CPvPRewardTerritory *pTerritory = new CPvPRewardTerritory();
							pTerritory->Set(x, X, y, Y, z, Z, PVP_REWARD_ZONE);
							pTerritory->SetRewardId(CParser::GetValueInt(sLine, "RewardId"));
							pTerritory->SetRewardCount(CParser::GetValueInt(sLine, "RewardCount"));
							pTerritory->SetRequiredLevel(CParser::GetValueInt(sLine, "RequiredLevel"));
							pTerritory->SetStealFromVictim(CParser::GetValueInt(sLine, "StealFromVictim"));
							pTerritory->SetCheckingHWID(CParser::GetValueInt(sLine, "CheckHWID"));
							pTerritory->SetKillReuse(CParser::GetValueInt(sLine, "KillReuse"));
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "WAR_REWARD_ZONE")
						{
							CWarRewardTerritory *pTerritory = new CWarRewardTerritory();
							pTerritory->Set(x, X, y, Y, z, Z, WAR_REWARD_ZONE);
							pTerritory->SetRewardId(CParser::GetValueInt(sLine, "RewardId"));
							pTerritory->SetRewardCount(CParser::GetValueInt(sLine, "RewardCount"));
							pTerritory->SetRequiredLevel(CParser::GetValueInt(sLine, "RequiredLevel"));
							pTerritory->SetStealFromVictim(CParser::GetValueInt(sLine, "StealFromVictim"));
							pTerritory->SetCheckingHWID(CParser::GetValueInt(sLine, "CheckHWID"));
							pTerritory->SetKillReuse(CParser::GetValueInt(sLine, "KillReuse"));
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "PK_REWARD_ZONE")
						{
							CPkRewardTerritory *pTerritory = new CPkRewardTerritory();
							pTerritory->Set(x, X, y, Y, z, Z, PK_REWARD_ZONE);
							pTerritory->SetRewardId(CParser::GetValueInt(sLine, "RewardId"));
							pTerritory->SetRewardCount(CParser::GetValueInt(sLine, "RewardCount"));
							pTerritory->SetRequiredLevel(CParser::GetValueInt(sLine, "RequiredLevel"));
							pTerritory->SetStealFromVictim(CParser::GetValueInt(sLine, "StealFromVictim"));
							pTerritory->SetCheckingHWID(CParser::GetValueInt(sLine, "CheckHWID"));
							pTerritory->SetKillReuse(CParser::GetValueInt(sLine, "KillReuse"));
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "NOPKZONE")
						{
							CNoPKZoneTerritory *pTerritory = new CNoPKZoneTerritory();
							pTerritory->Set(x, X, y, Y, z, Z, NOPKZONE);
							pTerritory->SetPenaltyTime(CParser::GetValueInt(sLine, "penaltyTime"));
							pTerritory->SetRequiredLevel(CParser::GetValueInt(sLine, "RequiredLevel"));

							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "EVENT_PENALTY_CLAN_ZONE")
						{
							CNoPKZoneTerritory *pTerritory = new CNoPKZoneTerritory();
							pTerritory->Set(x, X, y, Y, z, Z, EVENT_PENALTY_CLAN_ZONE);
							pTerritory->SetPenaltyTime(CParser::GetValueInt(sLine, "penaltyTime"));
							pTerritory->SetRequiredLevel(CParser::GetValueInt(sLine, "RequiredLevel"));

							string loc = Parser::ParseOptionString(sLine, "KickOutPos");
							if(loc.size() > 0)
							{
								loc = Parser::Replace(loc, '/', ' ');
								stringstream locStream(loc);
								FVector pos;
								if(locStream >> pos.x >> pos.y >> pos.z)
								{
									pTerritory->SetKickOutPos(pos.x, pos.y, pos.z);
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "DESPAWN_SUMMON_ZONE")
						{
							CDespawnSummonTerritory *pTerritory = new CDespawnSummonTerritory();
							pTerritory->Set(x, X, y, Y, z, Z, DESPAWN_SUMMON_ZONE);
							string sSkillList = Parser::ParseOptionString(sLine, "SummonList");
							sSkillList = CParser::Replace(sSkillList, ';', ' ');
							stringstream sstr;
							sstr << sSkillList;
							INT32 classId = 0;
							while(sstr >> classId)
							{
								pTerritory->Block(classId);
								classId = 0;
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "DISPEL_SKILL_ZONE")
						{
							CDispelSkillTerritory *pTerritory = new CDispelSkillTerritory();
							pTerritory->Set(x, X, y, Y, z, Z, DISPEL_SKILL_ZONE);
							string sSkillList = Parser::ParseOptionString(sLine, "SkillList");
							sSkillList = CParser::Replace(sSkillList, ';', ' ');
							stringstream sstr;
							sstr << sSkillList;
							string skillName;
							while(sstr >> skillName)
							{
								wstring wName = StringToWString(skillName);
								INT32 skillId = 0;
								INT32 level = 0;
								g_SkillDB.GetSkillIdLevelByName(wName.c_str(), &skillId, &level);
								if(skillId > 0 && level > 0)
								{
									pTerritory->Block(skillId, level);
								}else
								{
									g_Log.Add(CLog::Error, "[%s] Invalid skill name[%s]", __FUNCTION__, skillName.c_str());
								}
							}
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else if(sType == "MINING_ZONE")
						{
							CMiningTerritory *pTerritory = new CMiningTerritory();
							pTerritory->Set(x, X, y, Y, z, Z, MINING_ZONE);
							pTerritory->SetMiningId(Parser::ParseOptionInt(sLine, "MiningDataId"));
							mData.insert(pair<int, CTerritoryEx*>(ID, pTerritory));
						}else
						{
							g_Log.Add(CLog::Error, "[%s] Unknown Type[%s] territory_id[%d]", __FUNCTION__, sType.c_str(), ID);
						}
					}
				}
			}
			g_Log.Add(CLog::Blue, "[%s] Loaded[%d] Territories", __FUNCTION__, mData.size());
			file.close();
		}else
			g_Log.Add(CLog::Error, "[%s] Cannot find file[%s]", __FUNCTION__, sFile.c_str());
	}catch(...)
	{
		EXCEPTION_LOG;
	}
}

void CTerritoryChecker::GetTerritories(CCreature *pCreature, TerritoryData &td)
{
	if(pCreature->ValidCreature())
	{
		LockTerritory();
		map<int, CTerritoryEx*>::iterator Iter = mData.begin();
		for(;Iter!=mData.end();Iter++)
		{
			if(Iter->second->IsInside(pCreature->pSD->Pos.x, pCreature->pSD->Pos.y, pCreature->pSD->Pos.z))
			{
				if(Iter->second->GetType() != TERRITORY_NONE)
				{
					td.territoryId[Iter->second->GetType()] = Iter->first;
				}
			}
		}
		UnlockTerritory();
	}
}

int CTerritoryChecker::IsInTerritory(FVector& Pos, TerritoryType type)
{
	LockTerritory();
	map<int, CTerritoryEx*>::iterator Iter = mData.begin();
	for(;Iter!=mData.end();Iter++)
	{
		if(Iter->second->GetType() == type)
		{
			if(Iter->second->IsInside(Pos.x, Pos.y, Pos.z))
			{
				UnlockTerritory();
				return Iter->first;
			}
		}
	}
	UnlockTerritory();
	return 0;
}
int CTerritoryChecker::IsInTerritory(CCreature *pCreature, TerritoryType type)
{
	if(pCreature->ValidCreature())
	{
		LockTerritory();
		map<int, CTerritoryEx*>::iterator Iter = mData.begin();
		for(;Iter!=mData.end();Iter++)
		{
			if(Iter->second->GetType() == type)
			{
				if(Iter->second->IsInside(pCreature->pSD->Pos.x, pCreature->pSD->Pos.y, pCreature->pSD->Pos.z))
				{
					UnlockTerritory();
					return Iter->first;
				}
			}
		}
		UnlockTerritory();
	}
	return 0;
}

void CTerritoryChecker::ValidateRideTerritory(CCreature *pCreature)
{
	guard;

	if(User *pUser = pCreature->SafeCastUser())
	{
		int nYongmaType = pUser->pSD->nYongmaType;
		if( nYongmaType == 2) //Check for Fly Zone
		{
			if(pUser->pSD->pExData->territoryData.territoryId[FORBIDDEN_FLY_ZONE] != 0)
			{
				if(pUser->pSD->nGetOffTimer == 0)
				{
					pUser->pSocket->SendSystemMessage(SystemMessage::THIS_AREA_CANNOT_BE_ENTERED_WHILE_MOUNTED_ATOP_OF_A_WYVERN___YOU_WILL_BE_DISMOUNTED_FROM_YOUR_WYVERN_IF_YOU_DO_NOT_LEAVE_);
					pUser->pSD->pExData->TimerHandler.AddTimer(CCreatureTimerHandler::USER_DISMOUNT_WYVERN, 5);
					pUser->pSD->nGetOffTimer = 1;
				}
			}
		}else if( nYongmaType == 1 ) //Check for Ride Zone
		{
			if(pUser->pSD->pExData->territoryData.territoryId[FORBIDDEN_RIDE_ZONE] != 0)
			{
				pUser->pSocket->SendSystemMessage(L"You're not allowed to ride a strider here!");
				pUser->GetOff(true);
			}
		}
	}
	unguard;
}

CTerritoryEx *CTerritoryChecker::GetTerritory(int ID)
{
	LockTerritory();

	map<int, CTerritoryEx*>::iterator Iter = mData.find(ID);
	CTerritoryEx* result = NULL;
	if(Iter!=mData.end())
		result = Iter->second;

	UnlockTerritory();
	return result;
}