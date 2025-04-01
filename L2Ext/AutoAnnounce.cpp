#include "stdafx.h"
#include "AutoAnnounce.h"
#include "NpcDb.h"
#include "ObjectDB.h"
#include "TerritoryData.h"
#include "DB.h"

CAutoAnnounce g_AutoAnnounce;


wstring AnnounceStealMsg;
bool AnnounceSteal = false;
INT32 m_AnnounceStealMsgId = 0;


UINT m_SendMsgPickUp;
UINT m_AnnouncePickUpMsgItemId;
wstring m_AnnounceOnPickUpClan;
wstring m_AnnounceOnPickUpNormal;


CAutoAnnounce::CAutoAnnounce()
{
}

CAutoAnnounce::~CAutoAnnounce()
{
}


extern std::vector<std::pair<std::wstring, int> > AnnounceRaidBossAnticipado;

void CAutoAnnounce::Init()
{
	m_reload = FALSE;
	m_enabled = FALSE;
	mDarNoblesPorMatarBarakiel = FALSE;
	mDarEntradaPorMatarDarion = FALSE;
	m_data.clear();
	m_data2.clear();
	m_BossList.clear();
	m_BossEpicList.clear();
	LoadINI();
	if(m_enabled)
	{
		g_Log.Add(CLog::Blue, "Auto Announce feature is enabled. Loaded [%d] announces. Loaded [%d] static announces.", m_data.size(), m_data2.size());
	}
}

/*
[AutoAnnounce]
Enabled=1
AnnounceCount=2
Announce1_Message=Welcome to ServerName Lineage II Interlude server, hope you enjoy.
Announce1_ShowOnEnterWorld=1
Announce1_Interval=0
Announce2_Message=Please remember to vote for us, more info at www.servername.com thx in advance.
Announce2_ShowOnEnterWorld=1
Announce2_Interval=300

StaticAnnounceCount=2
StaticAnnounce1_Message=blablabla
StaticAnnounce1_Critical=1
StaticAnnounce1_DayFlag=1111111
StaticAnnounce1_Time=23:20
StaticAnnounce2_Message=blablabla
StaticAnnounce2_Critical=0
StaticAnnounce2_DayFlag=1111111
StaticAnnounce2_Time=23:20
*/

void CAutoAnnounce::LoadINI()
{
	const TCHAR* section = _T("AutoAnnounce");
	m_enabled = GetPrivateProfileInt(section, _T("Enabled"), 0, g_ConfigFile);
	UINT count = GetPrivateProfileInt(section, _T("AnnounceCount"), 0, g_ConfigFile);
	TCHAR temp[16384] = { 0 };
	m_BossAnnounce[0] = 0;
	m_BossAnnounce2[0] = 0;




	AnnounceOnBossAnticipoTime = GetPrivateProfileInt(section, _T("AnnounceOnBossAnticipoTime"), 0, g_ConfigFile);
	if(GetPrivateProfileString(section, _T("AnnounceOnBossSpawnAnticipo"), 0, temp, 16384, g_ConfigFile))
	{
		AnnounceOnBossSpawnAnticipo = temp;
	}



	AnnounceSteal = GetPrivateProfileInt(section, _T("AnnounceSteal"), 0, g_ConfigFile);
	memset(temp, 0, sizeof(temp));
	if(GetPrivateProfileString(section, _T("AnnounceStealMsg"), 0, temp, 8192, g_ConfigFile))
	{
		AnnounceStealMsg = temp;
	}
	
	m_AnnounceStealMsgId = GetPrivateProfileInt(section, _T("AnnounceStealMsgId"), 2679, g_ConfigFile);



	if(GetPrivateProfileString(section, _T("AnnounceOnBossSpawn"), 0, temp, 16384, g_ConfigFile))
	{
		m_BossAnnounce = temp;
	}
	if(GetPrivateProfileString(section, _T("AnnounceBossList"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream npcStream(temp);
		wstring npcName;
		while(npcStream >> npcName)
		{
			INT32 npcId = g_ObjectDB.GetClassIdFromName(npcName.c_str());
						//INT32 npcId = 0;
			if(npcId > 0)
			{
				m_BossList.push_back(npcId);


				bool comprobar = false;
				for (vector<pair<wstring, int>>::iterator Iter = AnnounceRaidBossAnticipado.begin(); Iter != AnnounceRaidBossAnticipado.end(); ++Iter) {
					if (Iter->first == npcName)
					{
						//Iter->second = 0;
						comprobar = true;
					}
				}

				if(!comprobar)
				{
					AnnounceRaidBossAnticipado.push_back(std::make_pair(npcName, 0));

				}




			}			
		}
	}


	if(GetPrivateProfileString(section, _T("AnnounceOnBossEpicSpawn"), 0, temp, 16384, g_ConfigFile))
	{
		m_BossAnnounce2 = temp;
	}
	if(GetPrivateProfileString(section, _T("AnnounceBossEpicList"), 0, temp, 0x8000, g_ConfigFile))
	{
		wstringstream npcStream(temp);
		wstring npcName;
		while(npcStream >> npcName)
		{
			INT32 npcId = g_ObjectDB.GetClassIdFromName(npcName.c_str());
						//INT32 npcId = 0;
			if(npcId > 0)
			{
				m_BossEpicList.push_back(npcId);
			}			
		}
	}





	//AnnouncePickUpMsgItemId=3435
	//SendMsgIdPickUp=2913
	//AnnouncePickUpNormal=Event Info: El player $pj a levantado el drop de evento.
	//AnnouncePickUpClan=Event Info: El player $pj del clan $clan a levantado el drop de evento.

	m_SendMsgPickUp = GetPrivateProfileInt(section, _T("SendMsgIdPickUp"), 2913, g_ConfigFile);
	m_AnnouncePickUpMsgItemId = GetPrivateProfileInt(section, _T("AnnouncePickUpMsgItemId"), 0, g_ConfigFile);

	if(GetPrivateProfileString(section, _T("AnnouncePickUpClan"), 0, temp, 16384, g_ConfigFile))
	{
		m_AnnounceOnPickUpClan = temp;
	}
	if(GetPrivateProfileString(section, _T("AnnouncePickUpNormal"), 0, temp, 16384, g_ConfigFile))
	{
		m_AnnounceOnPickUpNormal = temp;
	}





	m_SendMsgKill = GetPrivateProfileInt(section, _T("AnnounceBossMsgKillEnabled"), 0, g_ConfigFile);

	if(GetPrivateProfileString(section, _T("AnnounceOnBossKillClan"), 0, temp, 16384, g_ConfigFile))
	{
		m_AnnounceOnBossKillClan = temp;
	}
	if(GetPrivateProfileString(section, _T("AnnounceOnBossKill"), 0, temp, 16384, g_ConfigFile))
	{
		m_AnnounceOnBossKill = temp;
	}

	if(GetPrivateProfileString(section, _T("AnnounceOnBossKillNobless"), 0, temp, 16384, g_ConfigFile))
	{
		m_AnnounceOnBossKillNobless = temp;
	}


	if(GetPrivateProfileString(section, _T("AnnounceOnBossKillDarion"), 0, temp, 16384, g_ConfigFile))
	{
		m_AnnounceOnBossKillDarion = temp;
	}



	if(GetPrivateProfileString(section, _T("AnnounceOnBossEpicKill"), 0, temp, 16384, g_ConfigFile))
	{
		m_AnnounceOnBossEpicKill = temp;
	}
	if(GetPrivateProfileString(section, _T("AnnounceOnBossEpicKillClan"), 0, temp, 16384, g_ConfigFile))
	{
		m_AnnounceOnBossEpicKillClan = temp;
	}

	m_SendMsgKillEpicId = GetPrivateProfileInt(section, _T("SendMsgKillEpicId"), 2679, g_ConfigFile);
	m_SendMsgKillId = GetPrivateProfileInt(section, _T("SendMsgKillId"), 2759, g_ConfigFile);


	mDarNoblesPorMatarBarakiel = GetPrivateProfileInt(section, _T("DarNoblesPorMatarBarakiel"), 0, g_ConfigFile);

	mDarEntradaPorMatarDarion = GetPrivateProfileInt(section, _T("DarEntradaPorMatarDarion"), 0, g_ConfigFile);

	m_SendMsg = GetPrivateProfileInt(section, _T("AnnounceBossMsgEnabled"), 0, g_ConfigFile);
	m_SendMsgEpicId = GetPrivateProfileInt(section, _T("SendMsgEpicId"), 2679, g_ConfigFile);
	m_SendMsgId = GetPrivateProfileInt(section, _T("SendMsgId"), 2759, g_ConfigFile);

	for(UINT n = 0;n<count;n++)
	{
		AutoAnnounceData aad;
		aad.nextAnnounceTime = 0;
		{
			wstringstream keyStream;
			keyStream << L"Announce" << (n+1) <<L"_Message";
			if(GetPrivateProfileString(section, keyStream.str().c_str(), 0, temp, 8192, g_ConfigFile))
			{
				aad.announce = temp;
			}
		}
		{
			wstringstream keyStream;
			keyStream << L"Announce" << (n+1) <<L"_ShowOnEnterWorld";
			aad.onEnterWorld = GetPrivateProfileInt(section, keyStream.str().c_str(), 0, g_ConfigFile);
		}
		{
			wstringstream keyStream;
			keyStream << L"Announce" << (n+1) <<L"_Interval";
			aad.interval = GetPrivateProfileInt(section, keyStream.str().c_str(), 0, g_ConfigFile);
		}
		{
			wstringstream keyStream;
			keyStream << L"Announce" << (n+1) <<L"_CritAnnounce";
			aad.critAnnounce = GetPrivateProfileInt(section, keyStream.str().c_str(), 0, g_ConfigFile);
		}
		if(temp[0] != '\0')
		{
			m_data.push_back(aad);
		}
	}
	UINT count2 = GetPrivateProfileInt(section, _T("StaticAnnounceCount"), 0, g_ConfigFile);
	for(UINT n = 0;n<count2;n++)
	{
		StaticAnnounceData sad;
		sad.jobdone = false;
		sad.nextjobreset = 0;

		{
			wstringstream keyStream;
			keyStream << L"StaticAnnounce" << (n+1) <<L"_Message";
			if(GetPrivateProfileString(section, keyStream.str().c_str(), 0, temp, 8192, g_ConfigFile))
			{
				sad.announce = temp;
			}
		}
		{
			wstringstream keyStream;
			keyStream << L"StaticAnnounce" << (n+1) <<L"_Critical";
			sad.critAnnounce = GetPrivateProfileInt(section, keyStream.str().c_str(), 0, g_ConfigFile);
		}
		{
			wstringstream keyStream;
			keyStream << L"StaticAnnounce" << (n+1) <<L"_Time";
			if(GetPrivateProfileString(section, keyStream.str().c_str(), 0, temp, 8192, g_ConfigFile))
			{
				UINT hour, minute;

				wstring param(temp);
				param = Utils::ReplaceString(param, L";", L" ", true); 

				wstringstream paramStream(param);
				paramStream >> hour >> minute;
				
				//g_Log.Add(CLog::Blue, "hour[%d] min[%d]", hour, minute);

				sad.hour = hour;
				sad.min = minute;
			}
		}

		{
			wstringstream keyStream;
			keyStream << L"StaticAnnounce" << (n+1) <<L"_DayFlag";
			UINT dayFlag = GetPrivateProfileInt(section, keyStream.str().c_str(), 0, g_ConfigFile);
			for(UINT m = 0; m < 7; m++)
			{
				if((dayFlag % 10) == 1)
				{
					sad.dayFlag[m] = true;
				}else
				{
					sad.dayFlag[m] = false;
				}
				dayFlag /= 10;
			}
		}

		if(temp[0] != '\0')
		{
			m_data2.push_back(sad);
		}
	}
}

void CAutoAnnounce::TimerExpired()
{
	CTL;
	if(m_enabled || m_reload)
	{
		AUTO_LOCK(m_lock);
		if(m_reload)
		{
			Init();
			if(!m_enabled)
			{
				return;
			}
		}


		time_t currentTime = time(0);

		for (vector<pair<wstring, int>>::iterator Iter = AnnounceRaidBossAnticipado.begin(); Iter != AnnounceRaidBossAnticipado.end(); ++Iter) {


			if(currentTime == Iter->second - AnnounceOnBossAnticipoTime)
			{
				//g_Log.Add(CLog::Error, "[%s] Announce faltan 5 minutos!!!![%S] ", __FUNCTION__, Iter->first.c_str());



				//AnnounceOnBossAnticipoTime=60
				//AnnounceOnBossSpawnAnticipo=Raidboss Info: $bossName Aparecera en 1 minuto.

					int npcId = g_ObjectDB.GetClassIdFromName(Iter->first.c_str());
					wstring npcName = g_NpcDb.GetClientNameByClassId(npcId);
					wstring announce = AnnounceOnBossSpawnAnticipo;
					size_t pos = announce.find(L"$bossName");
					while(pos != wstring::npos)
					{
						announce = announce.replace(pos, 9, npcName);
						pos = announce.find(L"$bossName");
					}

					if(m_SendMsg)
					{
						CSystemMessage msg(m_SendMsgId);
						msg.AddText(announce.c_str());
						L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
					}
					else
					{
						//pUser->pSocket->Send("cddSS", 0x4A, 0, 0xA, L"", data.announce.c_str());
						CHAR buff[8190] = { 0 };
						int len = Assemble(buff, sizeof(buff), "cddSS", 0x4A, 0, 0xA, L"", announce.c_str());
						L2Server::BroadcastToAllUser(len, buff);
					}


			}
		}


		for(UINT n=0;n<m_data.size();n++)
		{
			AutoAnnounceData& data = m_data[n];
			if(data.interval > 0)
			{
				if(currentTime > data.nextAnnounceTime)
				{
					//announce and set new next announce time
					data.nextAnnounceTime = currentTime + data.interval;

					if(!data.critAnnounce)
					{
						Utils::BroadcastToAllUser_Announce(data.announce.c_str());
					}
					else
					{
						Utils::BroadcastToAllUser_Announce(data.announce.c_str());
						//CHAR pck[8190];
						//int nSize = Assemble(pck, 8190, "cddSS", 0x4A, 0, 18, L"", data.announce.c_str());
						//L2Server::BroadcastToAllUser(nSize, pck);
					}
				}
			}
		}

		tm ti;
		GetTimeInfo(ti);
		//Static Announces
		for(UINT n=0;n<m_data2.size();n++)
		{
			StaticAnnounceData& data = m_data2[n];
			if(!m_data2[n].jobdone)
			{
				if(data.dayFlag[ti.tm_wday])
				{
					//g_Log.Add(CLog::Blue, "HERE1");
					//g_Log.Add(CLog::Blue, "TM H[%d], D H[%d], TM M[%d], D M[%d]", ti.tm_hour, data.hour, ti.tm_min, data.min);
					if( (ti.tm_hour == data.hour) && (ti.tm_min == data.min) )
					{
						m_data2[n].jobdone = true;
						m_data2[n].nextjobreset = time(0) + 70;
						if(!data.critAnnounce)
							Utils::BroadcastToAllUser_Announce(data.announce.c_str());
						else
						{
							//CHAR pck[8190];
							//int nSize = Assemble(pck, 8190, "cddSS", 0x4A, 0, 18, L"", data.announce.c_str());
							//L2Server::BroadcastToAllUser(nSize, pck);

							Utils::BroadcastToAllUser_Announce(data.announce.c_str());


							//CSystemMessage msg(2679);
							//msg.AddText(data.announce.c_str());
							//L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
						}
					}
				}
			}

			if(m_data2[n].nextjobreset < time(0))
			{
				m_data2[n].jobdone = false;
			}
		}
	}
}

void CAutoAnnounce::OnEnterWorld(User *pUser)
{
	CTL;
	if(m_enabled)
	{
		if(pUser->ValidUser())
		{
			AUTO_LOCK(m_lock);
			for(UINT n=0;n<m_data.size();n++)
			{
				AutoAnnounceData& data = m_data[n];
				if(data.onEnterWorld)
				{
					if(!data.critAnnounce)
					{
						int MsgId = 0;
						std::wstring wAnnounce2;

						const std::wstring wDelimiter = L";;;";
						size_t nPos = wDelimiter.size();
						size_t nDelimiterPos = std::wstring(data.announce.c_str()).find(wDelimiter);
						if (nDelimiterPos != std::wstring::npos)
						{
							std::wstringstream ss(std::wstring(data.announce.c_str()).substr(0, nDelimiterPos));
							ss >> MsgId;
							wAnnounce2 = std::wstring(data.announce.c_str()).substr(nDelimiterPos + nPos);
						}
						else
						{
							wAnnounce2 = data.announce.c_str();
						}

						if (MsgId == 0)
						{
							pUser->pSocket->Send("cddSS", 0x4A, 0, 0xA, L"", data.announce.c_str());
						}
						else
						{
							CSystemMessage msg(MsgId);
							msg.AddText(wAnnounce2.c_str());
							pUser->SendSystemMessage(&msg);
						}
						
					}
					else
					{
						int MsgId = 0;
						std::wstring wAnnounce2;

						const std::wstring wDelimiter = L";;;";
						size_t nPos = wDelimiter.size();
						size_t nDelimiterPos = std::wstring(data.announce.c_str()).find(wDelimiter);
						if (nDelimiterPos != std::wstring::npos)
						{
							std::wstringstream ss(std::wstring(data.announce.c_str()).substr(0, nDelimiterPos));
							ss >> MsgId;
							wAnnounce2 = std::wstring(data.announce.c_str()).substr(nDelimiterPos + nPos);
						}
						else
						{
							wAnnounce2 = data.announce.c_str();
						}

						if (MsgId == 0)
						{
							pUser->pSocket->Send("cddSS", 0x4A, 0, 0xA, L"", data.announce.c_str());
						}
						else
						{
							CSystemMessage msg(MsgId);
							msg.AddText(wAnnounce2.c_str());
							pUser->SendSystemMessage(&msg);
						}
					}
				}
			}		
		}
	}
}

void CAutoAnnounce::OnBossEnterWorld(UINT npcClassId)
{
	CTL;
	if(m_enabled)
	{
		bool affected = false;
		bool epic = false;
		for(UINT n=0;n<m_BossList.size();n++)
		{
			if(m_BossList[n] == npcClassId)
			{
				affected = true;
				break;
			}
		}

		for(UINT n=0;n<m_BossEpicList.size();n++)
		{
			if(m_BossEpicList[n] == npcClassId)
			{
				affected = true;
				epic = true;
				break;
			}
		}

		if(affected)
		{
			//make an announce
			wstring npcName = g_NpcDb.GetClientNameByClassId(npcClassId);
			wstring announce = m_BossAnnounce;
			wstring announce2 = m_BossAnnounce2;
			size_t pos = announce.find(L"$bossName");
			while(pos != wstring::npos)
			{
				announce = announce.replace(pos, 9, npcName);
				pos = announce.find(L"$bossName");
			}

			pos = announce2.find(L"$bossName");
			while(pos != wstring::npos)
			{
				announce2 = announce2.replace(pos, 9, npcName);
				pos = announce2.find(L"$bossName");
			}


			
			wstring DBnpcName = g_NpcDb.GetDbNameByClassId(npcClassId);
			for (vector<pair<wstring, int>>::iterator Iter = AnnounceRaidBossAnticipado.begin(); Iter != AnnounceRaidBossAnticipado.end(); ++Iter) {
				if (Iter->first == DBnpcName)
				{
					Iter->second = 0;
					break;
				}
			}



			if(m_SendMsg)
			{
				if(epic)
				{
					CSystemMessage msg(m_SendMsgEpicId);
					//msg.AddText(npcName.c_str());
					msg.AddText(announce2.c_str());
					L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
					
				}
				else
				{
					CSystemMessage msg(m_SendMsgId);
					msg.AddText(announce.c_str());
					L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
				}
			}
			else
			{
				//pUser->pSocket->Send("cddSS", 0x4A, 0, 0xA, L"", data.announce.c_str());
				CHAR buff[8190] = { 0 };
				int len = Assemble(buff, sizeof(buff), "cddSS", 0x4A, 0, 0xA, L"", announce.c_str());
				L2Server::BroadcastToAllUser(len, buff);
			}
		}
	}
}






void CAutoAnnounce::OnBossKillWorld(UINT npcClassId, CCreature *pKiller)
{
	CTL;
	if(m_enabled)
	{
		bool affected = false;
		bool epic = false;
		for(UINT n=0;n<m_BossList.size();n++)
		{
			if(m_BossList[n] == npcClassId)
			{
				affected = true;
				break;
			}
		}

		for(UINT n=0;n<m_BossEpicList.size();n++)
		{
			if(m_BossEpicList[n] == npcClassId)
			{
				affected = true;
				epic = true;
				break;
			}
		}

		if(affected)
		{
			if(m_SendMsgKill && pKiller->ValidCreature())
			{

				wstring DBnpcName = g_NpcDb.GetDbNameByClassId(npcClassId);
				for (vector<pair<wstring, int>>::iterator Iter = AnnounceRaidBossAnticipado.begin(); Iter != AnnounceRaidBossAnticipado.end(); ++Iter) {
					if (Iter->first == DBnpcName)
					{
						Iter->second = -1;
						break;
					}
				}

				User *pUser = pKiller->GetUser();
				if (pUser->ValidUser())
				{
					bool nTieneClan = false;
					wstring npcName = g_NpcDb.GetClientNameByClassId(npcClassId);
					wstring AnnounceOnBossKillClan =  m_AnnounceOnBossKillClan;
					wstring AnnounceOnBossKill =  m_AnnounceOnBossKill;
					wstring AnnounceOnBossEpicKill =  m_AnnounceOnBossEpicKill;
					wstring AnnounceOnBossEpicKillClan =  m_AnnounceOnBossEpicKillClan;
					wstring nClanName = L"";

					wstring AnnounceOnBossKillNobless =  m_AnnounceOnBossKillNobless;

					wstring AnnounceOnBossKillDarion =  m_AnnounceOnBossKillDarion;

					CPledge *pPledge = pKiller->GetUser()->GetPledge();
					CPledgeSharedData *pSD = pPledge->GetSharedData();
					if(pSD)
					{
						if(pPledge)
						{
							nClanName = pPledge->pSD->wszClanName;
							nTieneClan = true;
						}
					}

					if(epic)
					{
						if(nTieneClan)
						{
							wstringstream name;
							name << pKiller->pSD->wszName;
							wstring charname;
							name >> charname;

							wstring announce = AnnounceOnBossEpicKillClan;
							size_t pos = announce.find(L"$bossName");
							while(pos != wstring::npos)
							{
								announce = announce.replace(pos, 9, npcName);
								pos = announce.find(L"$bossName");
							}

							pos = announce.find(L"$clan");
							while(pos != wstring::npos)
							{
								announce = announce.replace(pos, 5, nClanName);
								pos = announce.find(L"$clan");
							}

							pos = announce.find(L"$pj");
							while(pos != wstring::npos)
							{
								announce = announce.replace(pos, 3, charname);
								pos = announce.find(L"$pj");
							}

							CSystemMessage msg(m_SendMsgKillEpicId);
							msg.AddText(announce.c_str());
							L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
						}
						else
						{
							wstringstream name;
							name << pKiller->pSD->wszName;
							wstring charname;
							name >> charname;

							wstring announce = AnnounceOnBossEpicKill;
							size_t pos = announce.find(L"$bossName");
							while(pos != wstring::npos)
							{
								announce = announce.replace(pos, 9, npcName);
								pos = announce.find(L"$bossName");
							}

							pos = announce.find(L"$pj");
							while(pos != wstring::npos)
							{
								announce = announce.replace(pos, 3, charname);
								pos = announce.find(L"$pj");
							}

							CSystemMessage msg(m_SendMsgKillEpicId);
							msg.AddText(announce.c_str());
							L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
						}
					}
					else
					{
						if(nTieneClan)
						{
							wstringstream name;
							name << pKiller->pSD->wszName;
							wstring charname;
							name >> charname;

							wstring announce = AnnounceOnBossKillClan;
							size_t pos = announce.find(L"$bossName");
							while(pos != wstring::npos)
							{
								announce = announce.replace(pos, 9, npcName);
								pos = announce.find(L"$bossName");
							}

							pos = announce.find(L"$clan");
							while(pos != wstring::npos)
							{
								announce = announce.replace(pos, 5, nClanName);
								pos = announce.find(L"$clan");
							}

							pos = announce.find(L"$pj");
							while(pos != wstring::npos)
							{
								announce = announce.replace(pos, 3, charname);
								pos = announce.find(L"$pj");
							}

							CSystemMessage msg(m_SendMsgKillId);
							msg.AddText(announce.c_str());
							L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
						}
						else
						{
							wstringstream name;
							name << pKiller->pSD->wszName;
							wstring charname;
							name >> charname;

							wstring announce = AnnounceOnBossKill;
							size_t pos = announce.find(L"$bossName");
							while(pos != wstring::npos)
							{
								announce = announce.replace(pos, 9, npcName);
								pos = announce.find(L"$bossName");
							}

							pos = announce.find(L"$pj");
							while(pos != wstring::npos)
							{
								announce = announce.replace(pos, 3, charname);
								pos = announce.find(L"$pj");
							}

							CSystemMessage msg(m_SendMsgKillId);
							msg.AddText(announce.c_str());
							L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
						}
					}


							if(npcClassId == 1025325 && mDarNoblesPorMatarBarakiel)
							{


								//map<UINT, double> accumulatedContribute = pNpc->pContributeData->accumulatedContribute;


								if(CParty *pParty = pUser->GetParty())
								{
									UserVector vUsers;
									pParty->GetAllMembersEx(vUsers);
									for(UINT n=0;n<vUsers.size();n++)
									{
										if(User *pMember = vUsers[n]->SafeCastUser())
										{
											if(!pMember->pSD->nNobless && pMember->pSD->nAlive)
											{
												g_DB.RequestSaveNoblessType(pMember, 1);
												pMember->AddItemToInventory(7694, 1);	//noblesse tiara
												typedef void(*f)(LPBYTE, INT32, bool);
												f(0x431360L)(pMember->pSD->OneTimeQuestBitMap, 247, true);
												g_DB.SaveQuestInfo(pMember);
												//2545	1	a,Congratulations! You've became a noblesse.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
												pMember->pSocket->SendSystemMessage(2545);
												pMember->PlaySound(L"ItemSound.quest_finish", 1, pMember->nObjectID, (int)pMember->pSD->Pos.x, (int)pMember->pSD->Pos.y, (int)pMember->pSD->Pos.z);

												wstringstream name;
												name << pMember->pSD->wszName;
												wstring charname;
												name >> charname;

												wstring announce = AnnounceOnBossKillNobless;
												size_t pos = announce.find(L"$pj");
												while(pos != wstring::npos)
												{
													announce = announce.replace(pos, 3, charname);
													pos = announce.find(L"$pj");
												}

												CSystemMessage msg(2902);
												msg.AddText(announce.c_str());
												L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
											}
										}
									}
								}
								else
								{
									if(!pUser->pSD->nNobless)
									{
										g_DB.RequestSaveNoblessType(pUser, 1);
										pUser->AddItemToInventory(7694, 1);	//noblesse tiara
										typedef void(*f)(LPBYTE, INT32, bool);
										f(0x431360L)(pUser->pSD->OneTimeQuestBitMap, 247, true);
										g_DB.SaveQuestInfo(pUser);
										//2545	1	a,Congratulations! You've became a noblesse.\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
										pUser->pSocket->SendSystemMessage(2545);
										pUser->PlaySound(L"ItemSound.quest_finish", 1, pUser->nObjectID, (int)pUser->pSD->Pos.x, (int)pUser->pSD->Pos.y, (int)pUser->pSD->Pos.z);

										wstringstream name;
										name << pUser->pSD->wszName;
										wstring charname;
										name >> charname;

										wstring announce = AnnounceOnBossKillNobless;
										size_t pos = announce.find(L"$pj");
										while(pos != wstring::npos)
										{
											announce = announce.replace(pos, 3, charname);
											pos = announce.find(L"$pj");
										}

										CSystemMessage msg(2902);
										msg.AddText(announce.c_str());
										L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
									}
								}

								  
								g_TerritoryChecker.AddZonePvP2(1025325, 91272, -86103, -2712);
							}


							//[darion] = 1025601
							if(npcClassId == 1025601 && mDarEntradaPorMatarDarion)
							{
								if(CParty *pParty = pUser->GetParty())
								{
									UserVector vUsers;
									pParty->GetAllMembersEx(vUsers);
									for(UINT n=0;n<vUsers.size();n++)
									{
										if(User *pMember = vUsers[n]->SafeCastUser())
										{
											CItem *pItem = pMember->inventory.GetFirstItemByClassID(9641);
											if(pItem->IsValidItem())
											{

											}else
											{
												if(pMember->pSD->nAlive)
												{
													pMember->AddItemToInventory(9641, 1);	//entrada al siege

													wstringstream name;
													name << pMember->pSD->wszName;
													wstring charname;
													name >> charname;

													wstring announce = AnnounceOnBossKillDarion;
													size_t pos = announce.find(L"$pj");
													while(pos != wstring::npos)
													{
														announce = announce.replace(pos, 3, charname);
														pos = announce.find(L"$pj");
													}

													CSystemMessage msg(2902);
													msg.AddText(announce.c_str());
													L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
												}
											}
										}
									}
								}
								else
								{
									CItem *pItem = pUser->inventory.GetFirstItemByClassID(9641);
									if(pItem->IsValidItem())
									{

									}else
									{
										pUser->AddItemToInventory(9641, 1);	//entrada al siege

										wstringstream name;
										name << pUser->pSD->wszName;
										wstring charname;
										name >> charname;

										wstring announce = AnnounceOnBossKillDarion;
										size_t pos = announce.find(L"$pj");
										while(pos != wstring::npos)
										{
											announce = announce.replace(pos, 3, charname);
											pos = announce.find(L"$pj");
										}

										CSystemMessage msg(2902);
										msg.AddText(announce.c_str());
										L2Server::BroadcastToAllUser(msg.GetSize(), msg.GetBuff());
									}
								}
							}


				}

			}
			else
			{

			}
		}
	}
}