#include "StdAfx.h"
#include "IndividualVote.h"
#include "DB.h"
#include "HtmlCache.h"
#include "CUrlFunc.h"
#include "PlayerAction.h"

CIndivVote g_IndivVote;

CIndivVote::CIndivVote() : m_Enabled(FALSE), m_Loaded(FALSE), m_TerminateThread(false), m_ThreadHandle(0)
{
}

CIndivVote::~CIndivVote()
{
	//if(m_ThreadHandle)
	//{
	//	m_TerminateThread = true;
	//}
}

void CIndivVote::Init()
{
	m_CheckCycle = 600; //Check Every 10 minutes
	LoadData();
	if(m_Enabled)
	{
		g_Log.Add(CLog::Blue, "[%s] Feature is enabled.", __FUNCTION__);
		//if(m_ThreadHandle == NULL)
		//	m_ThreadHandle = (HANDLE)_beginthread(CIndivVote::JobThread, 0, 0);
		//else
		//	g_Log.Add(CLog::Error, "[%s] Couldn't Start Thread for Vote Reward System.", __FUNCTION__);

		//Test();
		g_DB.RequestLoadVoteReward();
	}
}
/*
[VoteReward]
Enabled=1
;l2topzone.com
L2Topzone_Enable=1
L2Topzone_RewardId=57
L2Topzone_RewardQuanity=100
;Default 12hours = 43200
L2Topzone_Cycle=43200
L2Topzone_API=b32492088c6dd507318122394e7bc1fd
L2Topzone_VoteLink=

;l2.hopzone.net
L2Hopzone_Enable=1
L2Hopzone_RewardId=57
L2Hopzone_RewardQuanity=100
L2Hopzone_Cycle=300
L2Hopzone_API=ml607i3gi9M7aIwB
L2Hopzone_VoteLink=

;l2network.eu
L2Network_Enable=1
L2Network_RewardId=57
L2Network_RewardQuanity=100
;Default 10hours = 36000
L2Network_Cycle=36000
L2Network_API=99ece41313e75dfdf3be0eb99b609cea
L2Network_VoteLink=

;top.l2jbrasil.com
L2JBrazil_Enable=1
L2JBrazil_RewardId=57
L2JBrazil_RewardQuanity=100
L2JBrazil_Cycle=
L2JBrazil_API=
L2JBrazil_VoteLink=

;L2Servers.com
L2Servers_Enable=1
L2Servers_RewardId=57
L2Servers_RewardQuanity=100
L2Servers_Cycle=
L2Servers_ServerId=
L2Servers_API=
L2Servers_VoteLink=
*/
void CIndivVote::LoadData()
{
	const TCHAR* sectionName = _T("VoteReward");
	m_Enabled = GetPrivateProfileInt(sectionName, _T("Enabled"), 0, g_ConfigFile);
	m_CheckCycleReminder = GetPrivateProfileInt(sectionName, _T("ReminderCheckCyle"), 1200, g_ConfigFile);
	TCHAR temp[8190] = { 0 };
	//m_PendingJobLimit = GetPrivateProfileInt(sectionName, _T("PendingJobLimit"), 50, g_ConfigFile);

	//L2Topzone
	m_TopZoneEnable = GetPrivateProfileInt(sectionName, _T("L2Topzone_Enable"), 0, g_ConfigFile);
	m_TopZoneRewardId = GetPrivateProfileInt(sectionName, _T("L2Topzone_RewardId"), 0, g_ConfigFile);
	m_TopZoneRewardQuanity = GetPrivateProfileInt(sectionName, _T("L2Topzone_RewardQuanity"), 0, g_ConfigFile);
	m_TopZoneCycle = GetPrivateProfileInt(sectionName, _T("L2Topzone_Cycle"), 0, g_ConfigFile); //12hours = 43200
	if(GetPrivateProfileString(sectionName, _T("L2Topzone_API"), 0, temp, 8190, g_ConfigFile))
	{
		m_TopZoneAPI = WStringToString(temp);
	}
	if(GetPrivateProfileString(sectionName, _T("L2Topzone_VoteLink"), 0, temp, 8190, g_ConfigFile))
	{
		m_TopZoneVoteLink = temp;
	}
	//L2Hopzone
	m_HopZoneEnable = GetPrivateProfileInt(sectionName, _T("L2Hopzone_Enable"), 0, g_ConfigFile);
	m_HopZoneRewardId = GetPrivateProfileInt(sectionName, _T("L2Hopzone_RewardId"), 0, g_ConfigFile);
	m_HopZoneRewardQuanity = GetPrivateProfileInt(sectionName, _T("L2Hopzone_RewardQuanity"), 0, g_ConfigFile);
	m_HopZoneCycle = GetPrivateProfileInt(sectionName, _T("L2Hopzone_Cycle"), 0, g_ConfigFile);
	if(GetPrivateProfileString(sectionName, _T("L2Hopzone_API"), 0, temp, 8190, g_ConfigFile))
	{
		m_HopZoneAPI = WStringToString(temp);
	}
	if(GetPrivateProfileString(sectionName, _T("L2Hopzone_VoteLink"), 0, temp, 8190, g_ConfigFile))
	{
		m_HopZoneVoteLink = temp;
	}
	//L2Network
	m_L2NetworkEnable = GetPrivateProfileInt(sectionName, _T("L2Network_Enable"), 0, g_ConfigFile);
	m_L2NetworkRewardId = GetPrivateProfileInt(sectionName, _T("L2Network_RewardId"), 0, g_ConfigFile);
	m_L2NetworkRewardQuanity = GetPrivateProfileInt(sectionName, _T("L2Network_RewardQuanity"), 0, g_ConfigFile);
	m_L2NetworkCycle = GetPrivateProfileInt(sectionName, _T("L2Network_Cycle"), 0, g_ConfigFile); //10hours = 36000
	if(GetPrivateProfileString(sectionName, _T("L2Network_API"), 0, temp, 8190, g_ConfigFile))
	{
		m_L2NetworkAPI = WStringToString(temp);
	}
	if(GetPrivateProfileString(sectionName, _T("L2Network_VoteLink"), 0, temp, 8190, g_ConfigFile))
	{
		m_L2NetworkVoteLink = temp;
	}
	//L2JBrazil
	m_L2jBrazilEnable = GetPrivateProfileInt(sectionName, _T("L2JBrazil_Enable"), 0, g_ConfigFile);
	m_L2jBrazilRewardId = GetPrivateProfileInt(sectionName, _T("L2JBrazil_RewardId"), 0, g_ConfigFile);
	m_L2jBrazilRewardQuanity = GetPrivateProfileInt(sectionName, _T("L2JBrazil_RewardQuanity"), 0, g_ConfigFile);
	m_L2jBrazilCycle = GetPrivateProfileInt(sectionName, _T("L2JBrazil_Cycle"), 0, g_ConfigFile);
	if(GetPrivateProfileString(sectionName, _T("L2JBrazil_API"), 0, temp, 8190, g_ConfigFile))
	{
		m_L2jBrazilAPI = WStringToString(temp);
	}
	if(GetPrivateProfileString(sectionName, _T("L2JBrazil_VoteLink"), 0, temp, 8190, g_ConfigFile))
	{
		m_L2jBrazilVoteLink = temp;
	}
	//L2Servers
	m_L2ServersEnable = GetPrivateProfileInt(sectionName, _T("L2Servers_Enable"), 0, g_ConfigFile);
	m_L2ServersRewardId = GetPrivateProfileInt(sectionName, _T("L2Servers_RewardId"), 0, g_ConfigFile);
	m_L2ServersRewardQuanity = GetPrivateProfileInt(sectionName, _T("L2Servers_RewardQuanity"), 0, g_ConfigFile);
	m_L2ServersCycle = GetPrivateProfileInt(sectionName, _T("L2Servers_Cycle"), 0, g_ConfigFile);
	m_L2ServersServerId = GetPrivateProfileInt(sectionName, _T("L2Servers_ServerId"), 0, g_ConfigFile);
	if(GetPrivateProfileString(sectionName, _T("L2Servers_API"), 0, temp, 8190, g_ConfigFile))
	{
		m_L2ServersAPI = WStringToString(temp);
	}
	if(GetPrivateProfileString(sectionName, _T("L2Servers_VoteLink"), 0, temp, 8190, g_ConfigFile))
	{
		m_L2ServersVoteLink = temp;
	}
}

void CIndivVote::LoadFromDBFinished()
{
	guard;
	
	if(m_Enabled)
	{
		m_Loaded = true;
		g_Log.Add(CLog::Blue, "[%s] Load Done!", __FUNCTION__, m_Loaded);
	}

	unguard;
}

void CIndivVote::AddDatabase(CIPAddress IPaddr, UINT l2topzone, UINT l2topzoneReward, UINT l2hopzone, UINT l2hopzoneReward, UINT l2network, UINT l2networkReward, 
							 UINT l2jbrasil, UINT l2jbrasilReward, UINT l2servers, UINT l2serversReward, UINT l2mmotop, UINT l2mmotopReward, UINT lastchecked, UINT lastcheckedreminder, HWID hwid)
{
	guard;

	CDatabaseVotes *db = new CDatabaseVotes();
	db->IPaddr = IPaddr;
	db->l2topzone = l2topzone;
	db->l2topzoneReward = l2topzoneReward;
	db->l2hopzone = l2hopzone;
	db->l2hopzoneReward = l2hopzoneReward;
	db->l2network = l2network;
	db->l2networkReward = l2networkReward;
	db->l2jbrasil = l2jbrasil;
	db->l2jbrasilReward = l2jbrasilReward;
	db->l2servers = l2servers;
	db->l2serversReward = l2serversReward;
	db->l2mmotop = l2mmotop;
	db->l2mmotopReward = l2mmotopReward;
	db->lastchecked = lastchecked;
	db->lastcheckedreminder = lastcheckedreminder;
	db->hwid = hwid;

	m_LockDB.Enter();

	bool m_exist = false;
	for(vector<pair<CIPAddress,CDatabaseVotes*>>::iterator Iter = m_Database.begin(); Iter!=m_Database.end();Iter++)
	{
		if(Iter->first == IPaddr)
			m_exist = true;
	}

	if(!m_exist)
	{
		m_Database.push_back(pair<CIPAddress,CDatabaseVotes*>(IPaddr, db));
		//g_Log.Add(CLog::Error, "[%s] Added!", __FUNCTION__);
	}
	else
		g_Log.Add(CLog::Error, "[%s] IP Already Exist into DB!", __FUNCTION__);

	m_LockDB.Leave();

	unguard;
}

void CIndivVote::DeleteFromDatabase(CIPAddress IPaddr)
{
	guard;

	m_LockDB.Enter();
	for(vector<pair<CIPAddress,CDatabaseVotes*>>::iterator Iter = m_Database.begin(); Iter!=m_Database.end();Iter++)
	{
		if(Iter->first == IPaddr)
		{
			m_Database.erase(Iter);
			break;
		}
	}
	m_LockDB.Leave();
	unguard;
}

void CIndivVote::UpdateDatabaseRecord(CIPAddress IPaddr, UINT UpdateCategory, UINT value, UINT value2, BOOL updatelastchecked)
{
	guard;

	bool found = false;
	m_LockDB.Enter();
	for(vector<pair<CIPAddress,CDatabaseVotes*>>::iterator Iter = m_Database.begin(); Iter!=m_Database.end();Iter++)
	{
		if(Iter->first == IPaddr)
		{
			found = true;
			if(UpdateCategory == 1)
			{
				Iter->second->l2topzone = value;
				Iter->second->l2topzoneReward = value2;
				if(updatelastchecked)
					Iter->second->lastchecked = time(0) + m_CheckCycle;
			}
			else if(UpdateCategory == 2)
			{
				Iter->second->l2hopzone = value;
				Iter->second->l2hopzoneReward = value2;
				if(updatelastchecked)
					Iter->second->lastchecked = time(0) + m_CheckCycle;
			}
			else if(UpdateCategory == 3)
			{
				Iter->second->l2network = value;
				Iter->second->l2networkReward = value2;
				if(updatelastchecked)
					Iter->second->lastchecked = time(0) + m_CheckCycle;
			}
			else if(UpdateCategory == 4)
			{
				Iter->second->l2jbrasil = value;
				Iter->second->l2jbrasilReward = value2;
				if(updatelastchecked)
					Iter->second->lastchecked = time(0) + m_CheckCycle;
			}
			else if(UpdateCategory == 5)
			{
				Iter->second->l2servers = value;
				Iter->second->l2serversReward = value2;
				if(updatelastchecked)
					Iter->second->lastchecked = time(0) + m_CheckCycle;
			}
			else if(UpdateCategory == 6)
			{
				Iter->second->l2mmotop = value;
				Iter->second->l2mmotopReward = value2;
				if(updatelastchecked)
					Iter->second->lastchecked = time(0) + m_CheckCycle;
			}
			else if(UpdateCategory == 7)
			{
				Iter->second->lastchecked = value;
			}
			else if(UpdateCategory == 8)
			{
				Iter->second->lastcheckedreminder = value;
			}

			//For now is disabled
			if(false)
			{
				CDatabaseVotes *db = Iter->second;

				g_DB.RequestSaveVoteReward(db->IPaddr.ToWString().c_str(), db->l2topzone, db->l2topzoneReward, db->l2hopzone, db->l2hopzoneReward, db->l2network, db->l2networkReward, db->l2jbrasil, 
					db->l2jbrasilReward, db->l2servers, db->l2serversReward, db->l2mmotop, db->l2mmotopReward, db->lastchecked, db->hwid.ToString().c_str());
			}

			//TODO SEND TO DB THE CHANGE

			break;
		}
	}
	m_LockDB.Leave();

	if(!found)
		g_Log.Add(CLog::Error, "[%s] Couldn't Update the Value For a Topsite! Debug[%d][%d][%d]!", __FUNCTION__, UpdateCategory, value, value2);

	unguard;
}

void CIndivVote::UpdateDatabaseRecord(HWID hwid, UINT UpdateCategory, UINT value, UINT value2, BOOL updatelastchecked)
{
	guard;

	bool found = false;
	m_LockDB.Enter();
	for(vector<pair<CIPAddress,CDatabaseVotes*>>::iterator Iter = m_Database.begin(); Iter!=m_Database.end();Iter++)
	{
		if(Iter->second->hwid == hwid)
		{
			found = true;
			if(UpdateCategory == 1)
			{
				Iter->second->l2topzone = value;
				Iter->second->l2topzoneReward = value2;
				if(updatelastchecked)
					Iter->second->lastchecked = time(0) + m_CheckCycle;
			}
			else if(UpdateCategory == 2)
			{
				Iter->second->l2hopzone = value;
				Iter->second->l2hopzoneReward = value2;
				if(updatelastchecked)
					Iter->second->lastchecked = time(0) + m_CheckCycle;
			}
			else if(UpdateCategory == 3)
			{
				Iter->second->l2network = value;
				Iter->second->l2networkReward = value2;
				if(updatelastchecked)
					Iter->second->lastchecked = time(0) + m_CheckCycle;
			}
			else if(UpdateCategory == 4)
			{
				Iter->second->l2jbrasil = value;
				Iter->second->l2jbrasilReward = value2;
				if(updatelastchecked)
					Iter->second->lastchecked = time(0) + m_CheckCycle;
			}
			else if(UpdateCategory == 5)
			{
				Iter->second->l2servers = value;
				Iter->second->l2serversReward = value2;
				if(updatelastchecked)
					Iter->second->lastchecked = time(0) + m_CheckCycle;
			}
			else if(UpdateCategory == 6)
			{
				Iter->second->l2mmotop = value;
				Iter->second->l2mmotopReward = value2;
				if(updatelastchecked)
					Iter->second->lastchecked = time(0) + m_CheckCycle;
			}
			else if(UpdateCategory == 7)
			{
				Iter->second->lastchecked = value;
			}
			else if(UpdateCategory == 8)
			{
				Iter->second->lastcheckedreminder = value;
			}

			//For now is disabled
			if(false)
			{
				CDatabaseVotes *db = Iter->second;

				g_DB.RequestSaveVoteReward(db->IPaddr.ToWString().c_str(), db->l2topzone, db->l2topzoneReward, db->l2hopzone, db->l2hopzoneReward, db->l2network, db->l2networkReward, db->l2jbrasil, 
					db->l2jbrasilReward, db->l2servers, db->l2serversReward, db->l2mmotop, db->l2mmotopReward, db->lastchecked, db->hwid.ToString().c_str());
			}

			//TODO SEND TO DB THE CHANGE

			break;
		}
	}
	m_LockDB.Leave();

	if(!found)
		g_Log.Add(CLog::Error, "[%s] Couldn't Update the Value For a Topsite! Debug[%d][%d][%d]!", __FUNCTION__, UpdateCategory, value, value2);

	unguard;
}

CDatabaseVotes* CIndivVote::GetFromDatabase(CIPAddress IPaddr)
{
	guard;
	CDatabaseVotes *pDb = NULL;

	m_LockDB.Enter();
	for(vector<pair<CIPAddress,CDatabaseVotes*>>::iterator Iter = m_Database.begin(); Iter!=m_Database.end();Iter++)
	{
		if(Iter->first == IPaddr)
		{
			pDb = Iter->second;
		}
	}
	m_LockDB.Leave();

	unguard;
	return pDb;
}

CDatabaseVotes* CIndivVote::GetFromDatabase(HWID hwid)
{
	guard;
	CDatabaseVotes *pDb = NULL;
	CDatabaseVotes *pDb2 = NULL;

	CDatabaseVotes *pDbReturn = new CDatabaseVotes();
	pDbReturn->l2topzoneReward = 0;
	pDbReturn->l2hopzoneReward = 0;
	pDbReturn->l2networkReward = 0;
	pDbReturn->l2jbrasilReward = 0;
	pDbReturn->l2serversReward = 0;
	pDbReturn->l2mmotopReward = 0;
	pDbReturn->lastchecked = 0;
	pDbReturn->lastcheckedreminder = 0;
	pDbReturn->hwid = hwid;

	m_LockDB.Enter();
	for(vector<pair<CIPAddress,CDatabaseVotes*>>::iterator Iter = m_Database.begin(); Iter!=m_Database.end();Iter++)
	{
		pDb = Iter->second;
		if(pDb->hwid == hwid)
		{
			//pDb2 = Iter->second;
			if(pDb->l2topzoneReward > pDbReturn->l2topzoneReward)
				pDbReturn->l2topzoneReward = pDb->l2topzoneReward;

			if(pDb->l2hopzoneReward > pDbReturn->l2hopzoneReward)
				pDbReturn->l2hopzoneReward = pDb->l2hopzoneReward;

			if(pDb->l2networkReward > pDbReturn->l2networkReward)
				pDbReturn->l2networkReward = pDb->l2networkReward;

			if(pDb->l2jbrasilReward > pDbReturn->l2jbrasilReward)
				pDbReturn->l2jbrasilReward = pDb->l2jbrasilReward;

			if(pDb->l2serversReward > pDbReturn->l2serversReward)
				pDbReturn->l2serversReward = pDb->l2serversReward;

			if(pDb->l2mmotopReward > pDbReturn->l2mmotopReward)
				pDbReturn->l2mmotopReward = pDb->l2mmotopReward;

			if(pDb->lastchecked > pDbReturn->lastchecked)
				pDbReturn->lastchecked = pDb->lastchecked;

			if(pDb->lastcheckedreminder > pDbReturn->lastcheckedreminder)
				pDbReturn->lastcheckedreminder = pDb->lastcheckedreminder;

		}
	}
	m_LockDB.Leave();

	unguard;
	return pDbReturn;
}

bool CIndivVote::ExistInDB(CIPAddress IPaddr)
{
	guard;
	bool exist = false;

	m_LockDB.Enter();
	for(vector<pair<CIPAddress,CDatabaseVotes*>>::iterator Iter = m_Database.begin(); Iter!=m_Database.end();Iter++)
	{
		if(Iter->first == IPaddr)
		{
			exist = true;
		}
	}
	m_LockDB.Leave();

	unguard;
	return exist;
}

bool CIndivVote::ExistInDB(HWID hwid)
{
	guard;
	bool exist = false;
	CDatabaseVotes *pDb = NULL;

	m_LockDB.Enter();
	for(vector<pair<CIPAddress,CDatabaseVotes*>>::iterator Iter = m_Database.begin(); Iter!=m_Database.end();Iter++)
	{
		pDb = Iter->second;
		if(pDb->hwid == hwid)
		{
			exist = true;
		}
	}
	m_LockDB.Leave();

	unguard;
	return exist;
}

void CIndivVote::OnServerShutdown()
{
	guard;

	if(m_Enabled)
	{
		m_Loaded = false;

		m_LockDB.Enter();
		for(vector<pair<CIPAddress,CDatabaseVotes*>>::iterator Iter = m_Database.begin(); Iter!=m_Database.end();Iter++)
		{
			CDatabaseVotes *db = Iter->second;

			g_DB.RequestSaveVoteReward(db->IPaddr.ToWString().c_str(), db->l2topzone, db->l2topzoneReward, db->l2hopzone, db->l2hopzoneReward, db->l2network, db->l2networkReward, db->l2jbrasil, 
				db->l2jbrasilReward, db->l2servers, db->l2serversReward, db->l2mmotop, db->l2mmotopReward, db->lastchecked, db->hwid.ToString().c_str());
		}
		m_LockDB.Leave();
	}

	unguard;
}

void CIndivVote::CheckVoteUser(User *pUser, BOOL enterworld)
{
	guard;

	if(m_Enabled)
	{
		if(pUser->ValidUser())
		{
			if(m_Loaded)
			{
				bool m_msg_topzone = false;
				bool m_msg_hopzone = false;
				bool m_msg_l2network = false;
				bool m_msg_l2jbrazil = false;
				bool m_msg_l2servers = false;

				UINT LastChecked = pUser->pED->m_LastCheckVote;
				UINT CurrentTime = time(0);

				CIPAddress IPaddress = pUser->pSocket->pED->IPaddr;
				CDatabaseVotes *pDb = GetFromDatabase(IPaddress);
				CDatabaseVotes *pDb_hwid = GetFromDatabase(pUser->pSocket->pED->longHWID);

				if(pDb)
				{
					LastChecked = pDb->lastcheckedreminder;
					if( (LastChecked == 0) || (LastChecked < time(0)) || enterworld )
					{
						if( m_TopZoneEnable && ( (pDb->l2topzoneReward + m_TopZoneCycle) < CurrentTime) && ( (pDb_hwid->l2topzoneReward + m_TopZoneCycle) < CurrentTime) )
							m_msg_topzone = true;

						if( m_HopZoneEnable && ( (pDb->l2hopzoneReward + m_HopZoneCycle) < CurrentTime) && ( (pDb_hwid->l2hopzoneReward + m_HopZoneCycle) < CurrentTime) )
							m_msg_hopzone = true;

						if( m_L2NetworkEnable && ( (pDb->l2networkReward + m_L2NetworkCycle) < CurrentTime) && ( (pDb_hwid->l2networkReward + m_L2NetworkCycle) < CurrentTime) )
							m_msg_l2network = true;

						if( m_L2jBrazilEnable && ( (pDb->l2jbrasilReward + m_L2jBrazilCycle) < CurrentTime) && ( (pDb_hwid->l2jbrasilReward + m_L2jBrazilCycle) < CurrentTime) )
							m_msg_l2jbrazil = true;

						if( m_L2ServersEnable && ( (pDb->l2serversReward + m_L2ServersCycle) < CurrentTime) && ( (pDb_hwid->l2serversReward + m_L2ServersCycle) < CurrentTime) )
							m_msg_l2servers = true;
							
						if(LastChecked == 0)
						{
							LastChecked = time(0);
						}
						LastChecked = LastChecked + m_CheckCycleReminder;

						if( LastChecked < time(0) )
							LastChecked = time(0) + m_CheckCycleReminder;

						pUser->pED->m_LastCheckVote = LastChecked;

						UpdateDatabaseRecord(IPaddress, 8, LastChecked);
					}
				}
				else
				{
					//Add Record
					LastChecked = CurrentTime + m_CheckCycleReminder;
					AddDatabase(IPaddress, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, LastChecked, pUser->pSocket->pED->longHWID);
					pUser->pED->m_LastCheckVote = LastChecked;

					m_msg_topzone = true;
					m_msg_hopzone = true;
					m_msg_l2network = true;
					m_msg_l2jbrazil = true;
					m_msg_l2servers = true;
				}
	
				if(m_msg_topzone && m_TopZoneEnable)
				{
					pUser->SendSystemMessage(L"Vote: You can Vote For us on L2Topzone Topsite! Just do /vote !!");
				}
				if(m_msg_hopzone && m_HopZoneEnable)
				{
					pUser->SendSystemMessage(L"Vote: You can Vote For us on L2Hopzone Topsite! Just do /vote !!");
				}
				if(m_msg_l2network && m_L2NetworkEnable)
				{
					pUser->SendSystemMessage(L"Vote: You can Vote For us on L2Network Topsite! Just do /vote !!");
				}
				if(m_msg_l2jbrazil && m_L2jBrazilEnable)
				{
					pUser->SendSystemMessage(L"Vote: You can Vote For us on L2JBrasil Topsite! Just do /vote !!");
				}
				if(m_msg_l2servers && m_L2ServersEnable)
				{
					pUser->SendSystemMessage(L"Vote: You can Vote For us on L2Servers Topsite! Just do /vote !!");
				}
			}
		}
	}
	unguard;
}

void CIndivVote::OnShowVotePage(User *pUser)
{
	guard;

	if(pUser->ValidUser())
	{
		const WCHAR *wHtml = g_HtmlCache.Get(L"show_vote.htm");
		if(wHtml)
		{
			wstring html(wHtml);
			
			//Add IP Module on Vote Link
			CIPAddress IPaddress = pUser->pSocket->pED->IPaddr;
			wstring wTopzone = Utils::ReplaceString(m_TopZoneVoteLink, L"<?ip_player?>", IPaddress.ToWString(), true);
			wstring wHopzone = Utils::ReplaceString(m_HopZoneVoteLink, L"<?ip_player?>", IPaddress.ToWString(), true);
			wstring wNetwork = Utils::ReplaceString(m_L2NetworkVoteLink, L"<?ip_player?>", IPaddress.ToWString(), true);
			wstring wL2JBrasil = Utils::ReplaceString(m_L2jBrazilVoteLink, L"<?ip_player?>", IPaddress.ToWString(), true);
			wstring wL2Servers = Utils::ReplaceString(m_L2ServersVoteLink, L"<?ip_player?>", IPaddress.ToWString(), true);

			//L2Topzone
			html = Utils::ReplaceString(html, L"<?l2topzone?>", wTopzone, true);
			//L2Hopzone
			html = Utils::ReplaceString(html, L"<?l2hopzone?>", wHopzone, true);
			//L2Network
			html = Utils::ReplaceString(html, L"<?l2network?>", wNetwork, true);
			//L2JBrasil
			html = Utils::ReplaceString(html, L"<?l2jbrasil?>", wL2JBrasil, true);
			//L2Servers
			html = Utils::ReplaceString(html, L"<?l2servers?>", wL2Servers, true);

			PlayerAction::ShowHTML(pUser, L"show_vote.htm", html.c_str(), 0);
		}
	}

	unguard;
}
//g_Log.Add(CLog::Error, "[%s] Second[%d] CurrentTime[%d]", __FUNCTION__, pUser->pED->m_LastCheckVote, CurrentTime);
void CIndivVote::OnCheckUser(User *pUser)
{
	guard;

	CIPAddress IPaddress = pUser->pSocket->pED->IPaddr;
	HWID hwid = pUser->pSocket->pED->longHWID;

	if(ExistInDB(IPaddress))
	{
		CDatabaseVotes *pDb = GetFromDatabase(IPaddress);
		CDatabaseVotes *pDb_hwid = GetFromDatabase(hwid);

		//UINT m_CheckNext = m_CheckCycle + time(0);
		if(pDb->lastchecked < time(0) )
		{
			if(m_TopZoneEnable)
			{
				if( ( (pDb->l2topzoneReward + m_TopZoneCycle) < time(0) ) && ( (pDb_hwid->l2topzoneReward + m_TopZoneCycle) < time(0) ) )
					AddJobCheck(pUser,0);
				else
					pUser->SendSystemMessage(L"Vote: You have already took the reward for L2TopZone Site!");
			}

			if(m_HopZoneEnable)
			{
				if( ( (pDb->l2hopzoneReward + m_HopZoneCycle) < time(0) ) && ( (pDb_hwid->l2hopzoneReward + m_HopZoneCycle) < time(0) ) )
					AddJobCheck(pUser,1);
				else
					pUser->SendSystemMessage(L"Vote: You have already took the reward for L2HopZone Site!");
			}

			if(m_L2NetworkEnable)
			{
				if(  ( (pDb->l2networkReward + m_L2NetworkCycle) < time(0) ) && ( (pDb_hwid->l2networkReward + m_L2NetworkCycle) < time(0) ) )
					AddJobCheck(pUser,2);
				else
					pUser->SendSystemMessage(L"Vote: You have already took the reward for L2Network Site!");
			}

			if(m_L2jBrazilEnable)
			{
				if(  ( (pDb->l2jbrasilReward + m_L2jBrazilCycle) < time(0) ) && ( (pDb_hwid->l2jbrasilReward + m_L2jBrazilCycle) < time(0) ) )
					AddJobCheck(pUser,3);
				else
					pUser->SendSystemMessage(L"Vote: You have already took the reward for L2JBrazil Site!");
			}

			if(m_L2ServersEnable)
			{
				if(  ( (pDb->l2serversReward + m_L2ServersCycle) < time(0) ) && ( (pDb_hwid->l2serversReward + m_L2ServersCycle) < time(0) ) )
					AddJobCheck(pUser,4);
				else
					pUser->SendSystemMessage(L"Vote: You have already took the reward for L2Servers Site!");
			}

			UINT LastChecked = time(0) + m_CheckCycleReminder;
			UpdateDatabaseRecord(IPaddress, 7, LastChecked);
		}
		else
			pUser->SendSystemMessage(L"Vote: You can make a vote reward check one time per 10 minutes!");
	}
	else
	{
		if(ExistInDB(hwid))
		{
			AddDatabase(IPaddress, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, pUser->pSocket->pED->longHWID);

			CDatabaseVotes *pDb_hwid = GetFromDatabase(hwid);

			if(pDb_hwid->lastchecked < time(0) )
			{
				if(m_TopZoneEnable)
				{
					if((pDb_hwid->l2topzoneReward + m_TopZoneCycle) < time(0) )
						AddJobCheck(pUser,0);
					else
						pUser->SendSystemMessage(L"Vote: You have already took the reward for L2TopZone Site!");
				}

				if(m_HopZoneEnable)
				{
					if((pDb_hwid->l2hopzoneReward + m_HopZoneCycle) < time(0) )
						AddJobCheck(pUser,1);
					else
						pUser->SendSystemMessage(L"Vote: You have already took the reward for L2HopZone Site!");
				}

				if(m_L2NetworkEnable)
				{
					if((pDb_hwid->l2networkReward + m_L2NetworkCycle) < time(0) )
						AddJobCheck(pUser,2);
					else
						pUser->SendSystemMessage(L"Vote: You have already took the reward for L2Network Site!");
				}

				if(m_L2jBrazilEnable)
				{
					if((pDb_hwid->l2jbrasilReward + m_L2jBrazilCycle) < time(0) )
						AddJobCheck(pUser,3);
					else
						pUser->SendSystemMessage(L"Vote: You have already took the reward for L2JBrazil Site!");
				}

				if(m_L2ServersEnable)
				{
					if((pDb_hwid->l2serversReward + m_L2ServersCycle) < time(0) )
						AddJobCheck(pUser,4);
					else
						pUser->SendSystemMessage(L"Vote: You have already took the reward for L2Servers Site!");
				}

				UINT LastChecked = time(0) + m_CheckCycleReminder;
				UpdateDatabaseRecord(hwid, 7, LastChecked);
			}
			else
				pUser->SendSystemMessage(L"Vote: You can make a vote reward check one time per 10 minutes!");
		}
		else
		{
			//Add Record
			AddDatabase(IPaddress, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, pUser->pSocket->pED->longHWID);
			AddJobCheck(pUser,0);
			AddJobCheck(pUser,1);
			AddJobCheck(pUser,2);
			AddJobCheck(pUser,3);
			AddJobCheck(pUser,4);
			//TODO mmotop
		}
	}

	unguard;
}

void CIndivVote::AddJobCheck(User *pUser, UINT nSiteID)
{
	guard;
	VoteJobTodo Vj;
	Vj.Site = nSiteID;
	Vj.UserId = pUser->pSD->nDBID;
	Vj.IPaddr = pUser->pSocket->pED->IPaddr;
	Vj.hwid = pUser->pSocket->pED->longHWID;

	if(m_TopZoneEnable)
	{
		if(nSiteID == 0)
		{

		}
	}

	if(m_HopZoneEnable)
	{
		if(nSiteID == 1 )
		{
			//AddJobCheck(pUser,1);

			stringstream pathStream;
			pathStream << "https://api.hopzone.net/lineage2/vote?token=" << m_HopZoneAPI << "&ip_address=" << pUser->pSocket->pED->IPaddr.ToString(); //jobs[n].IPaddr.ToString()

			CHAR buff[8190];
			int len = Assemble(buff, 8190, "cds", 0x87, 0x07, pathStream.str().c_str());
			pUser->pSocket->Send("b", len, buff);
		}
	}

	if(m_L2NetworkEnable)
	{
		if( nSiteID == 2 )
		{
			//AddJobCheck(pUser,2);
			stringstream postdata;
			postdata << "apiKey=" << m_L2NetworkAPI << "&type=2&player=" << pUser->pSocket->pED->IPaddr.ToString(); //jobs[n].IPaddr.ToString()
			//string answer = g_CUrl.SendPostRequest("https://l2network.eu/api.php", postdata.str());

			CHAR buff[8190];
			int len = Assemble(buff, 8190, "cdss", 0x87, 0x06, "https://l2network.eu/api.php", postdata.str().c_str());
			pUser->pSocket->Send("b", len, buff);
		}
	}

	if(m_L2jBrazilEnable)
	{
		if( nSiteID == 3 )
		{
			//AddJobCheck(pUser,3);
			stringstream pathStream;
			pathStream << "https://top.l2jbrasil.com/votesystem/?ip=" << pUser->pSocket->pED->IPaddr.ToString() << "&username=" << m_L2jBrazilAPI; //jobs[n].IPaddr.ToString()

			CHAR buff[8190];
			int len = Assemble(buff, 8190, "cds", 0x87, 0x09, pathStream.str().c_str());
			pUser->pSocket->Send("b", len, buff);
		}
	}

	if(m_L2ServersEnable)
	{
		if( nSiteID == 4 )
		{
			//AddJobCheck(pUser,4);

			stringstream pathStream;
			pathStream << "https://www.l2servers.com/api/checkip.php?hash=" << m_L2ServersAPI << "&server_id=" << m_L2ServersServerId << "&ip=" << pUser->pSocket->pED->IPaddr.ToString(); //jobs[n].IPaddr.ToString()

			CHAR buff[8190];
			int len = Assemble(buff, 8190, "cds", 0x87, 0x08, pathStream.str().c_str());
			pUser->pSocket->Send("b", len, buff);
		}
	}

	unguard;
}

void CIndivVote::ClientAnswer(User *pUser, UINT nSiteID, UINT voteTime)
{
	guard;
	if(pUser->ValidUser())
	{
		if(nSiteID == 0) //L2Topzone
		{

		}
		else if(nSiteID == 1) //L2Hopzone
		{
			if(voteTime)
			{
				pUser->SendSystemMessage(L"Vote System: Your Vote at HopZone was Valid!");
				UpdateDatabaseRecord(pUser->pSocket->pED->IPaddr, 2, time(0), time(0), false);

				if(m_HopZoneRewardId && m_HopZoneRewardQuanity)
					pUser->AddItemToInventory(m_HopZoneRewardId, m_HopZoneRewardQuanity);
			}
			else
			{
				pUser->SendSystemMessage(L"Vote System: Your Vote at HopZone wasn't Valid! Please re-try again later!");
				UpdateDatabaseRecord(pUser->pSocket->pED->IPaddr, 2, time(0), 0, false);
			}
		}
		else if(nSiteID == 2) //L2Network
		{
			CDatabaseVotes *pDb = GetFromDatabase(pUser->pSocket->pED->IPaddr);
			UINT m_lastvote = pDb->l2network;
			
			bool bValidVote = false;
			if(voteTime > m_lastvote)
			{
				bValidVote = true;
			}

			//g_Log.Add(CLog::Error, "[%s] Vote time[%d][%d]!", __FUNCTION__, voteTime, m_lastvote);

			if(bValidVote)
			{
				pUser->SendSystemMessage(L"Vote System: Your Vote at L2Network was Valid!");
				UpdateDatabaseRecord(pUser->pSocket->pED->IPaddr, 3, time(0), time(0), false);

				if(m_L2NetworkRewardId && m_L2NetworkRewardQuanity)
					pUser->AddItemToInventory(m_L2NetworkRewardId, m_L2NetworkRewardQuanity);		
			}
			else
			{
				pUser->SendSystemMessage(L"Vote System: Your Vote at L2Network wasn't Valid! Please re-try again later!");
				UpdateDatabaseRecord(pUser->pSocket->pED->IPaddr, 3, time(0), 0, false);
			}
		}
		else if(nSiteID == 3) //L2JBrazil
		{
			if(voteTime)
			{
				pUser->SendSystemMessage(L"Vote System: Your Vote at L2JBrasil was Valid!");
				UpdateDatabaseRecord(pUser->pSocket->pED->IPaddr, 4, time(0), time(0), false);

				if(m_L2jBrazilRewardId && m_L2jBrazilRewardQuanity)
					pUser->AddItemToInventory(m_L2jBrazilRewardId, m_L2jBrazilRewardQuanity);
			}
			else
			{
				pUser->SendSystemMessage(L"Vote System: Your Vote at L2JBrasil wasn't Valid! Please re-try again later!");
				UpdateDatabaseRecord(pUser->pSocket->pED->IPaddr, 4, time(0), 0, false);
			}
		}
		else if(nSiteID == 4) //L2Servers
		{
			if(voteTime)
			{
				pUser->SendSystemMessage(L"Vote System: Your Vote at L2Servers was Valid!");
				UpdateDatabaseRecord(pUser->pSocket->pED->IPaddr, 5, time(0), time(0), false);

				if(m_L2ServersRewardId && m_L2ServersRewardQuanity)
					pUser->AddItemToInventory(m_L2ServersRewardId, m_L2ServersRewardQuanity);
			}
			else
			{
				pUser->SendSystemMessage(L"Vote System: Your Vote at L2Servers wasn't Valid! Please re-try again later!");
				UpdateDatabaseRecord(pUser->pSocket->pED->IPaddr, 5, time(0), 0, false);
			}	
		}

		UINT LastChecked = time(0) + m_CheckCycleReminder;
		UpdateDatabaseRecord(pUser->pSocket->pED->IPaddr, 7, LastChecked);
	}
	unguard;
}
/*
void CIndivVote::JobThread(LPVOID params)
{
	CIndivVote& m_This = g_IndivVote;

	while(m_This.m_TerminateThread == false)
	{
		vector<VoteJobTodo> jobs;
		m_This.m_Lock.Enter();
		jobs = m_This.m_PendingJobs;
		m_This.m_PendingJobs.clear();
		m_This.m_Lock.Leave();

		for(UINT n=0;n<jobs.size();n++)
		{
			if( jobs[n].Site == 0) //L2Topzone
			{
				stringstream pathStream;
				pathStream << "api.l2topzone.com/v1/vote?token=" << m_This.m_TopZoneAPI << "&ip=" << jobs[n].IPaddr.ToString(); //jobs[n].IPaddr.ToString()

				string answer = g_CUrl.SendGetRequest(pathStream.str());

				answer = m_This.ClearAnswer(answer);

				string validrequest = CParser::GetValueString(answer, "ok");
				bool bValidVote = false;
				UINT m_Votetime = 0;
				if(validrequest.compare("true") == 0 )
				{
					m_Votetime = time(0); //CParser::GetValueInt(answer, "voteTime");
					string validvote = CParser::GetValueString(answer, "isVoted");
					if(validvote.compare("true") == 0 )
					{
						bValidVote = true;
					}
				}

				if(bValidVote)
				{
					if(User *pUser = g_UserDB.GetUserByDBID(jobs[n].UserId))
					{
						pUser->SendSystemMessage(L"Vote System: Your Vote at TopZone was Valid!");
						m_This.UpdateDatabaseRecord(jobs[n].IPaddr, 1, time(0), time(0), false);

						if(m_This.m_TopZoneRewardId && m_This.m_TopZoneRewardQuanity)
							pUser->AddItemToInventory(m_This.m_TopZoneRewardId, m_This.m_TopZoneRewardQuanity);
					}
				}
				else
				{
					if(User *pUser = g_UserDB.GetUserByDBID(jobs[n].UserId))
					{
						pUser->SendSystemMessage(L"Vote System: Your Vote at TopZone wasn't Valid! Please re-try again later!");
						m_This.UpdateDatabaseRecord(jobs[n].IPaddr, 1, time(0), 0, false);
					}
				}

				//Do the action
			}

			if( jobs[n].Site == 1) //L2Hopzone
			{
				stringstream pathStream;
				pathStream << "https://api.hopzone.net/lineage2/vote?token=" << m_This.m_HopZoneAPI << "&ip_address=" << jobs[n].IPaddr.ToString(); //jobs[n].IPaddr.ToString()

				string answer = g_CUrl.SendGetRequest(pathStream.str());

				answer = m_This.ClearAnswer(answer);

				bool bValidVote = false;
				UINT m_Votetime = time(0); //CParser::GetValueInt(answer, "voteTime");
				string validvote = CParser::GetValueString(answer, "voted");
				if(validvote.compare("true") == 0 )
				{
					bValidVote = true;
				}

				if(bValidVote)
				{
					if(User *pUser = g_UserDB.GetUserByDBID(jobs[n].UserId))
					{
						pUser->SendSystemMessage(L"Vote System: Your Vote at HopZone was Valid!");
						m_This.UpdateDatabaseRecord(jobs[n].IPaddr, 2, time(0), time(0), false);

						if(m_This.m_HopZoneRewardId && m_This.m_HopZoneRewardQuanity)
							pUser->AddItemToInventory(m_This.m_HopZoneRewardId, m_This.m_HopZoneRewardQuanity);
					}
				}
				else
				{
					if(User *pUser = g_UserDB.GetUserByDBID(jobs[n].UserId))
					{
						pUser->SendSystemMessage(L"Vote System: Your Vote at HopZone wasn't Valid! Please re-try again later!");
						m_This.UpdateDatabaseRecord(jobs[n].IPaddr, 2, time(0), 0, false);
					}
				}
			}

			if( jobs[n].Site == 2) //L2Network
			{
				stringstream postdata;
				postdata << "apiKey=" << m_This.m_L2NetworkAPI << "&type=2&player=" << jobs[n].IPaddr.ToString(); //jobs[n].IPaddr.ToString()
				string answer = g_CUrl.SendPostRequest("https://l2network.eu/api.php", postdata.str());

				stringstream replyStream(answer);

				CDatabaseVotes *pDb = m_This.GetFromDatabase(jobs[n].IPaddr);
				UINT m_lastvote = pDb->l2network;

				bool bValidVote = false;
				INT32 voteTime = 0;
				UINT m_Votetime = 0;
				if(replyStream >> voteTime)
				{
					m_Votetime = time(0); //CParser::GetValueInt(answer, "voteTime");
					if(voteTime > 1)
					{
						if((UINT)voteTime > m_lastvote)
						{
							bValidVote = true;
						}
					}
				}

				if(bValidVote)
				{
					if(User *pUser = g_UserDB.GetUserByDBID(jobs[n].UserId))
					{
						pUser->SendSystemMessage(L"Vote System: Your Vote at L2Network was Valid!");
						m_This.UpdateDatabaseRecord(jobs[n].IPaddr, 3, time(0), time(0), false);

						if(m_This.m_L2NetworkRewardId && m_This.m_L2NetworkRewardQuanity)
							pUser->AddItemToInventory(m_This.m_L2NetworkRewardId, m_This.m_L2NetworkRewardQuanity);
					}		
				}
				else
				{
					if(User *pUser = g_UserDB.GetUserByDBID(jobs[n].UserId))
					{
						pUser->SendSystemMessage(L"Vote System: Your Vote at L2Network wasn't Valid! Please re-try again later!");
						m_This.UpdateDatabaseRecord(jobs[n].IPaddr, 3, time(0), 0, false);
					}
				}	
			}

			if( jobs[n].Site == 3) //L2JBrazil
			{
				stringstream pathStream;
				pathStream << "https://top.l2jbrasil.com/votesystem/?ip=" << jobs[n].IPaddr.ToString() << "&username=" << m_This.m_L2jBrazilAPI; //jobs[n].IPaddr.ToString()

				string answer = g_CUrl.SendGetRequest(pathStream.str());

				answer = m_This.ClearAnswer(answer, 1);

				bool bValidVote = false;
				UINT m_Votetime = 0;
				string validvote = CParser::GetValueString(answer, "status");
				if(validvote.compare("1") == 0 )
				{
					bValidVote = true;
					m_Votetime = time(0);
				}

				if(bValidVote)
				{
					if(User *pUser = g_UserDB.GetUserByDBID(jobs[n].UserId))
					{
						pUser->SendSystemMessage(L"Vote System: Your Vote at L2JBrasil was Valid!");
						m_This.UpdateDatabaseRecord(jobs[n].IPaddr, 4, time(0), time(0), false);

						if(m_This.m_L2jBrazilRewardId && m_This.m_L2jBrazilRewardQuanity)
							pUser->AddItemToInventory(m_This.m_L2jBrazilRewardId, m_This.m_L2jBrazilRewardQuanity);
					}		
				}
				else
				{
					if(User *pUser = g_UserDB.GetUserByDBID(jobs[n].UserId))
					{
						pUser->SendSystemMessage(L"Vote System: Your Vote at L2JBrasil wasn't Valid! Please re-try again later!");
						m_This.UpdateDatabaseRecord(jobs[n].IPaddr, 4, time(0), 0, false);
					}
				}	
			}

			if( jobs[n].Site == 4) //L2Servers
			{
				stringstream pathStream;
				pathStream << "https://www.l2servers.com/api/checkip.php?hash=" << m_This.m_L2ServersAPI << "&server_id=" << m_This.m_L2ServersServerId << "&ip=" << jobs[n].IPaddr.ToString(); //jobs[n].IPaddr.ToString()

				string answer = g_CUrl.SendGetRequest(pathStream.str());

				bool bValidVote = false;
				UINT m_Votetime = 0;
				if(answer.compare("TRUE") == 0 )
				{
					bValidVote = true;
					m_Votetime = time(0);
				}

				if(bValidVote)
				{
					if(User *pUser = g_UserDB.GetUserByDBID(jobs[n].UserId))
					{
						pUser->SendSystemMessage(L"Vote System: Your Vote at L2Servers was Valid!");
						m_This.UpdateDatabaseRecord(jobs[n].IPaddr, 5, time(0), time(0), false);

						if(m_This.m_L2ServersRewardId && m_This.m_L2ServersRewardQuanity)
							pUser->AddItemToInventory(m_This.m_L2ServersRewardId, m_This.m_L2ServersRewardQuanity);
					}
				}
				else
				{
					if(User *pUser = g_UserDB.GetUserByDBID(jobs[n].UserId))
					{
						pUser->SendSystemMessage(L"Vote System: Your Vote at L2Servers wasn't Valid! Please re-try again later!");
						m_This.UpdateDatabaseRecord(jobs[n].IPaddr, 5, time(0), 0, false);
					}
				}	
			}	
		}

		Sleep(1000);
	}

	_endthread();
}
*/
string CIndivVote::ClearAnswer(string answer, UINT type)
{
	guard;

	if(type == 0)
	{
		answer = CParser::Replace(answer, '{', ' ');
		answer = CParser::Replace(answer, '}', ' ');
		answer = CParser::Replace(answer, '""', ' ');
		answer = CParser::Replace(answer, '"', ' ');
		answer = CParser::Replace(answer, ' :', '=');
		answer = CParser::Trim(answer);
		answer = CParser::Replace(answer, ',', ' ');
	}
	else if(type == 1)
	{
		//answer = answer.erase(remove(answer.begin(), answer.end(), '\n'), answer.end());
		answer = CParser::Replace(answer, '\n', ' ');
		answer = CParser::Replace(answer, '>', '=');
		//answer = CParser::Replace(answer, '= ', ' ');

		answer = CParser::Replace(answer, '<', ' ');
	}

	unguard;
	return answer;
}

//FOR TESTING SITES
void CIndivVote::Test()
{
	guard;
				stringstream pathStream;
				pathStream << "https://www.l2servers.com/api/checkip.php?hash=" << m_L2ServersAPI << "&server_id=" << m_L2ServersServerId << "&ip=" << "94.69.161.193";

				//string answer = g_CUrl.SendGetRequest("api.hopzone.net/lineage2/vote?token=asd&ip_address=94.69.161.192");
				string answer = g_CUrl.SendGetRequest(pathStream.str());

				bool bValidVote = false;
				UINT m_Votetime = 0;
				if(answer.compare("TRUE") == 0 )
				{
					bValidVote = true;
					m_Votetime = time(0);
				}

				/*stringstream postdata;
				postdata << "apiKey=" << m_L2NetworkAPI << "&type=2&player=" << "94.69.161.192";
				string answer = g_CUrl.SendPostRequest("https://l2network.eu/api.php", postdata.str());

				stringstream replyStream(answer);

				INT32 voteTime = 0;
				if(replyStream >> voteTime)
				{
					bool bValidVote = false;
					UINT m_Votetime = time(0); //CParser::GetValueInt(answer, "voteTime");
					if(voteTime > 1)
					{
						bValidVote = true;
					
					}
				}*/

				//{"ok":false,"error_code":404,"description":"Ip you want to check is not an valid IP address","result":"127.0.0.1"}
				//{"ok":true,"error_code":0,"description":"","result":{"isVoted":true,"voteTime":"1557271015","serverTime":1557271480}}

				//answer = ClearAnswer(answer, 1);

				/*answer = CParser::Replace(answer, '{', ' ');
				answer = CParser::Replace(answer, '}', ' ');
				answer = CParser::Replace(answer, '""', ' ');
				answer = CParser::Replace(answer, '"', ' ');
				answer = CParser::Replace(answer, ' :', '=');
				answer = CParser::Trim(answer);
				answer = CParser::Replace(answer, ',', ' ');*/

				/*string validrequest = CParser::GetValueString(answer, "ok");
				bool bValidVote = false;
				if(validrequest.compare("true") == 0 )
				{
					UINT m_Votetime = CParser::GetValueInt(answer, "voteTime");
					string validvote = CParser::GetValueString(answer, "isVoted");
					if(validvote.compare("true") == 0 )
					{
						bValidVote = true;
					}

						stringstream nameStream;
						nameStream << "final.txt";
						ofstream file(nameStream.str().c_str());
						file << answer;
						file.close();
				}*/

				

	stringstream nameStream;
	nameStream << "answer.txt";
	ofstream file(nameStream.str().c_str());
	//file << answer;
	file << m_Votetime;
	file.close();

	unguard;
}
