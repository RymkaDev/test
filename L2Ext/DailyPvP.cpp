#include "stdafx.h"
#include "DailyPvP.h"
#include "DB.h"
#include "ObjectDB.h"

CDailyPvP g_DailyPvP;

BOOL m_AnnounceWinners;
INT32 m_AnnounceWinnersMsgId;
wstring m_AnnounceWinnersMsg;


INT32 m_RewardsSize;
INT32 m_RewardItemId[500];
INT32 m_RewardItemCount[500];

void CDailyPvP::Init()
{
	m_Enabled = FALSE;
	m_RequiredPvP = 20;
	m_MinLevel = 70;
	m_ItemReward = 57;
	m_ItemQuanity = 1;
	m_CleanUpTimestamp = time(0);
	m_HwidChk = TRUE;
	m_CustomZone = FALSE;
	m_ShowPoints = FALSE;
	LoadINI();
	if(m_Enabled)
	{
		g_Log.Add(CLog::Blue, "[%s] Feature is enabled.", __FUNCTION__);
		g_DB.RequestLoadDailyPvPEntry();
	}
}

/* INI section
[DailyPvP]
Enabled=1
RequiredPvP=20
MinLevel=70
ItemReward=57
ItemQuanity=1
UseCustomZone=0
HardwareIDCheck=1
*/

void CDailyPvP::OnDBLoad(UINT charId, LPBYTE lpHWID, UINT timestamp)
{
	guard;
	
	//checking time
	tm currentTime = { 0 };
	tm deathTime = { 0 };
	GetTimeInfo(currentTime);
	GetTimeInfo(deathTime, timestamp);
	if(currentTime.tm_mday == deathTime.tm_mday && currentTime.tm_mon == deathTime.tm_mon)
	{
		//add to db
		DailyPvPInfo dpi;
		dpi.charId = charId;
		memcpy(dpi.hardwareId.hash, lpHWID, 32);
		dpi.timestmap = timestamp;
		m_Lock.Enter();
		m_DB.push_back(dpi);
		m_Lock.Leave();
	}
	unguard;
}

void CDailyPvP::LoadINI()
{
	const TCHAR * section = _T("DailyPvP");
	m_Enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);
	m_RequiredPvP = GetPrivateProfileInt(section, _T("RequiredPvP"), 20, g_ConfigFile);
	m_MinLevel = GetPrivateProfileInt(section, _T("MinLevel"), 70, g_ConfigFile);
	m_ItemReward = GetPrivateProfileInt(section, _T("ItemReward"), 57, g_ConfigFile);
	m_ItemQuanity = GetPrivateProfileInt(section, _T("ItemQuanity"), 1, g_ConfigFile);
	m_HwidChk = GetPrivateProfileInt(section, _T("HardwareIDCheck"), 0, g_ConfigFile);
	m_CustomZone = GetPrivateProfileInt(section, _T("UseCustomZone"), 0, g_ConfigFile);
	m_MessageId = GetPrivateProfileInt(section, _T("MessageId"), 2901, g_ConfigFile);

	m_ShowPoints = GetPrivateProfileInt(section, _T("ShowPoints"), 0, g_ConfigFile);
	m_Time = GetPrivateProfileInt(section, _T("Time"), 60, g_ConfigFile);

	//AnnounceWinners=1
	//AnnounceWinnersMsgId=2901
	//AnnounceWinnersMsg=DailyPvP: $puesto# $charName con $points pvps.
	//RewardsSize=1
	//Rewards=adena:100

	m_AnnounceWinners = GetPrivateProfileInt(section, _T("AnnounceWinners"), 0, g_ConfigFile);
	m_AnnounceWinnersMsgId = GetPrivateProfileInt(section, _T("AnnounceWinnersMsgId"), 2901, g_ConfigFile);

	TCHAR temp[16384] = { 0 };
	if(GetPrivateProfileString(section, _T("AnnounceWinnersMsg"), 0, temp, 16384, g_ConfigFile))
	{
		m_AnnounceWinnersMsg = temp;
	}

	m_RewardsSize = GetPrivateProfileInt(section, _T("RewardsSize"), 0, g_ConfigFile);
	TCHAR sString[8192];	memset(sString, 0, sizeof(sString));
	if(GetPrivateProfileString(section, _T("Rewards"), 0, sString, sizeof(sString), g_ConfigFile))
	{
		tstringstream sstr; sstr << sString;
		tstring sValue;
		int n=0;
		while(sstr >> sValue)
		{
			size_t pos = sValue.find(_T(":"));
			tstring sItemNanme = sValue.substr(0, pos);
			int item_id = g_ObjectDB.GetClassIdFromName(sItemNanme.c_str());
			int item_count = _tstoi(sValue.substr(pos+1, (sValue.size() - pos - 1)).c_str());

			m_RewardItemId[n] = item_id;
			m_RewardItemCount[n] = item_count;

			n++;
		}
	}
}

bool CDailyPvP::GetPoint(User *pKiller, User *pEnemy)
{
	guard;
	bool ret = false;
	bool customzone = false;

	if(m_Enabled)
	{
		if(pKiller->ValidUser() && pEnemy->ValidUser())
		{
			if( m_CustomZone )
			{
				TerritoryData& td = pKiller->pSD->pExData->territoryData;
				if(td.territoryId[DAILY_PVP] != 0)
				{
					customzone = true;
				}
			}
			else
			{
				customzone = false;
			}

			if(!pKiller->pSocket->pED->longHWID.IsEqual(pEnemy->pSocket->pED->longHWID) )
			{
				//check for pledge/alliance/party
				if(!pKiller->IsInAlliance(pEnemy) && !pKiller->IsMyParty(pEnemy))
				{
					//check for min level
					if(pKiller->pSD->nLevel >= m_MinLevel && pEnemy->pSD->nLevel >= m_MinLevel)
					{
						//check for pvp amount - if player has less pvp points than required
						if(pKiller->pED->dailyPvPAmount < m_RequiredPvP)
						{
							bool canGet = true;
							bool updated = false;
							HWID& enemyHWID = pEnemy->pSocket->pED->longHWID;
							//checking if player with enemy hwid wasn't killed today
							//if he wasn't then add his hwid and timestamp to db (or update it)
							m_Lock.Enter();
							for(UINT n=0;n<m_DB.size();n++)
							{
								DailyPvPInfo& dpi = m_DB[n];
								//checking charId or hwid - so switching chars wont cause abusing the system
								if(dpi.charId == pEnemy->nDBID || dpi.hardwareId.IsEqual(enemyHWID))
								{
									//checking timestamp
									tm currentTime = { 0 };
									tm deathTime = { 0 };
									GetTimeInfo(currentTime);
									GetTimeInfo(deathTime, dpi.timestmap);
									if(currentTime.tm_min == deathTime.tm_min)
									{
										//player with this charId/hwid was already killed today
										canGet = false;
										break;
									}
									else
									{
										//player with this charId/hwid was killed but it was yesterday
										//updating old timestamp
										dpi.timestmap = time(0);
										updated = true;
										break;
									}


//									tm currentTime = { 0 };
//									tm deathTime = { 0 };
//									GetTimeInfo(currentTime);
//									GetTimeInfo(deathTime, dpi.timestmap);

									// Calcula la diferencia en segundos entre currentTime y deathTime
//									time_t currentTimeInSeconds = mktime(&currentTime);
//									time_t deathTimeInSeconds = mktime(&deathTime);
//									double timeDifference = difftime(currentTimeInSeconds, deathTimeInSeconds);

//									if (timeDifference <= m_Time) {
										// La diferencia es menor o igual a 5 minutos
//										canGet = false;
//										break;
//									} else {
//										dpi.timestmap = time(0);
//										updated = true;
//										break;
//									}

								}
							}
							if(canGet && !updated)
							{
								//add new entry to db - player with this charId/hwid wasn't killed before
								DailyPvPInfo dpi;
								dpi.charId = pEnemy->nDBID;
								dpi.timestmap = time(0);
								dpi.hardwareId = enemyHWID;
								m_DB.push_back(dpi);
							}
							m_Lock.Leave();

							if(canGet)
							{
								pKiller->pED->dailyPvPAmount++;
								pKiller->pED->dailyPvPTimestamp = time(0);
								//Send info to player 
								ShowPoints(pKiller);
								//save info in db
								g_DB.RequestSaveDailyPvP(pKiller->nDBID, pKiller->pED->dailyPvPAmount, pKiller->pED->dailyPvPTimestamp);
								g_DB.RequestSaveDailyPvPEntry(pEnemy->nDBID, enemyHWID.hash, time(0));

								ret = true;
								if(pKiller->pED->dailyPvPAmount == m_RequiredPvP)
								{
									//give reward or whatever you'd like to do when they gather all required points here
									pKiller->AddItemToInventory(m_ItemReward, m_ItemQuanity, false, 0);
								}
							}
							else
							{
								CSystemMessage msg(m_MessageId);
								msg.AddText(L"No se suman PvP/PK, lo mataste mas de una ves en poco tiempo.");
								pKiller->SendSystemMessage(&msg);
							}
						}
					}
				}
				else
				{
					CSystemMessage msg(m_MessageId);
					msg.AddText(L"No se suman PvP/PK, player en el mismo Clan, Allianza o Party.");
					pKiller->SendSystemMessage(&msg);
				}
			}
			else
			{
				CSystemMessage msg(m_MessageId);
				msg.AddText(L"No se suman PvP/PK, player en la misma PC.");
				pKiller->SendSystemMessage(&msg);

			}
		}
	}
	else
	{
		ret = true;
	}

	unguard;
	return ret;
}

//Timer expried for player
void CDailyPvP::TimerExpired(User *pUser)
{
	guard;
	if(m_Enabled)
	{
		//check when was the last time player get pvp point (checking if it was today if not then reset the amount)
		if(pUser->pED->dailyPvPTimestamp != 0)
		{
			tm currentTime = { 0 };
			tm lastPvPTime = { 0 };
			GetTimeInfo(currentTime);
			GetTimeInfo(lastPvPTime, pUser->pED->dailyPvPTimestamp);
			if(currentTime.tm_mday != lastPvPTime.tm_mday || currentTime.tm_mon != lastPvPTime.tm_mon)
			{
				//resetting the points and time
				pUser->pED->dailyPvPAmount = 0;
				pUser->pED->dailyPvPTimestamp = 0;
		//		g_DB.RequestSaveDailyPvP(pUser->nDBID, 0, 0);	//charId, points, timestamp
				//send info to user if neccessary
				ShowPoints(pUser);
			}
		}
	}
	unguard;
}

bool CDailyPvP::ReplyWinners(CDBSocket *pSocket, const unsigned char* packet, UINT packetId)
{

	guard;
	UINT puesto = 0;
	UINT points = 0;
	UINT charId = 0;
	WCHAR wName[25] = { 0 };

	int n = 1;
	int count;
	packet = Disassemble(packet, "d", &count);
	for (int i=0; i<count; i++) {
		packet = Disassemble(packet, "dSd", &charId, sizeof(wName), wName, &points);

		//HACER ANNOUNCE DE LOS GANADORES
		wstringstream name;
		name << wName;
		wstring charname;
		name >> charname;

		wstring announce = m_AnnounceWinnersMsg;
		size_t pos = announce.find(L"$charName");
		while(pos != wstring::npos)
		{
			announce = announce.replace(pos, 9, charname);
			pos = announce.find(L"$charName");
		}

		announce = Utils::ReplaceString(announce, _T("$puesto"), n, true);
		announce = Utils::ReplaceString(announce, _T("$points"), points, true);
		
		CSystemMessage msg(m_AnnounceWinnersMsgId);
		msg.AddText(announce.c_str());
		L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());

		g_DB.RequestItemDeliveryAdd(charId, m_RewardItemId[i], m_RewardItemCount[i], 0, 0);

		n++;
	}



//	Disassemble(packet, "dSdd", &charId, sizeof(wName), wName, &puesto, &points);
//	if(puesto > 0 && m_AnnounceWinners)
//	{
		//HACER ANNOUNCE DE LOS GANADORES
//		wstringstream name;
//		name << wName;
//		wstring charname;
//		name >> charname;

//		wstring announce = m_AnnounceWinnersMsg;
//		size_t pos = announce.find(L"$charName");
//		while(pos != wstring::npos)
//		{
//			announce = announce.replace(pos, 9, charname);
//			pos = announce.find(L"$charName");
//		}

//		announce = Utils::ReplaceString(announce, _T("$puesto"), puesto, true);
//		announce = Utils::ReplaceString(announce, _T("$points"), points, true);
		
//		CSystemMessage msg(m_AnnounceWinnersMsgId);
//		msg.AddText(announce.c_str());
//		L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());

//		g_DB.RequestItemDeliveryAdd(charId, m_RewardItemId[puesto-1], m_RewardItemCount[puesto-1], 0, 0);
//	}




	return true;
	unguard;
}


void CDailyPvP::TerminarEvento()
{
	guard;
	if(m_Enabled)
	{
		//cleaning up db
		m_CleanUpTimestamp = time(0);
		BYTE hwid[32];
		memset(hwid, 0, 32);
		g_DB.RequestSaveDailyPvPEntry(0, hwid, m_RewardsSize);	//this will signal clean up in cached
		m_Lock.Enter();
		//cleaning local db
		m_DB.clear();
		m_Lock.Leave();
		//players will get updated automatically in first timer expired function
	}
	unguard;
}


//timer expired for system
void CDailyPvP::TimerExpired()
{
	guard;
	if(m_Enabled)
	{
		//check if cleanup is needed
		tm currentTime = { 0 };
		tm cleanUpTime = { 0 };
		GetTimeInfo(currentTime);
		GetTimeInfo(cleanUpTime, m_CleanUpTimestamp);
		if(currentTime.tm_mday != cleanUpTime.tm_mday || currentTime.tm_mon != cleanUpTime.tm_mon)
		{
			//cleaning up db
			m_CleanUpTimestamp = time(0);
			BYTE hwid[32];
			memset(hwid, 0, 32);
			g_DB.RequestSaveDailyPvPEntry(0, hwid, m_RewardsSize);	//this will signal clean up in cached
			m_Lock.Enter();
			//cleaning local db
			m_DB.clear();
			m_Lock.Leave();
			//players will get updated automatically in first timer expired function
		}
	}
	unguard;
}

void CDailyPvP::ShowPoints(User *pUser)
{
	guard;
	if(m_Enabled && m_ShowPoints)
	{
		tm currentTime = { 0 };
		GetTimeInfo(currentTime);
		pUser->ShowPCCafePoints(m_RequiredPvP - pUser->pED->dailyPvPAmount, 0, 23 - currentTime.tm_hour, false);
	}
	unguard;
}