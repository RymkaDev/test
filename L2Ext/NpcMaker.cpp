#include "StdAfx.h"
#include "DB.h"
#include "ObjectDB.h"
#include "PlayerAction.h"

IVector teleportPos;

extern double teleportEpicPer;

CNpcSpawnDefine::CNpcSpawnDefine() : npcClassId(0), x(0), y(0), z(0), heading(0), x2(0), y2(0), z2(0), heading2(0), x3(0), y3(0), z3(0), heading3(0), startHour(-1), endHour(-1), respawnTime(0), saveInDB(0), spawnTime(0), deathTime(0), npcObjectId(0)
{
	memset(dayFlag, 0, sizeof(dayFlag));
}

CNpcSpawnEventDefine::CNpcSpawnEventDefine() : eventID(0), startHour(-1), endHour(-1)
{
	memset(dayFlag, 0, sizeof(dayFlag));
}

CNpcMaker::CNpcMaker()
{
	InitializeCriticalSection(&lock);
	m_enabled = FALSE;
	loadedFromDB = false;
	requestedDB = false;
	requestReload = false;
	teleportPos.x = 0;
	teleportPos.y = 0;
	teleportPos.z = 0;
}

CNpcMaker::~CNpcMaker()
{

	DeleteCriticalSection(&lock);
}

void CNpcMaker::Initialize()
{
	m_enabled = FALSE;
	ReadData();
	if(m_enabled)
	{
		g_Log.Add(CLog::Blue, "NpcMakerEx feature is enabled. Loaded [%d] npcs.",  lData.size());
		g_Log.Add(CLog::Blue, "NpcMakerEx feature is enabled. Loaded [%d] Events.",  lData2.size());
	}
}

void CNpcMaker::ReadData()
{
	ifstream file(g_ChangeFolders.NpcPosEx_txt.c_str());
	Lock();
	if(file)
	{
		DespawnAll();
		string sLine;
		while(getline(file, sLine))
		{
			//npc_pos_begin	npc_class_id=100100	start_date=2010-10-29-20-00	spawn_reuse=3600	spawn_x=12111	spawn_y=123123	spawn_z=2321	save_in_db=0	npc_pos_end;
			if(sLine.find("//") == 0)
				continue;
			if(sLine.find("setting_begin") == 0)
			{
				m_enabled = CParser::GetValueInt(sLine, "enabled");
			}else if(sLine.find("npc_pos_begin") == 0)
			{
				CNpcSpawnDefine data;
				data.spawnTime = 0;
				data.deathTime = 0;

				data.npcClassId = CParser::GetValueInt(sLine, "npc_class_id");
				string sStart = CParser::GetValueString(sLine, "start_date");
				if(sStart.size() > 1)
				{
					int year, month, day, hour, minute;
					sscanf(sStart.c_str(), "%d-%d-%d-%d-%d", &year, &month, &day, &hour, &minute);

					data.startDate = ConvertTime(year, month, day, hour, minute);
				}else
					data.startDate = 0;

				string sEnd = CParser::GetValueString(sLine, "end_date");
				if(sEnd.size() > 1)
				{
					int year, month, day, hour, minute;
					sscanf(sEnd.c_str(), "%d-%d-%d-%d-%d", &year, &month, &day, &hour, &minute);
					
					data.endDate = ConvertTime(year, month, day, hour, minute);
				}else
					data.endDate = INT_MAX;
			
				UINT dayFlag = CParser::GetValueInt(sLine, "day_flag", 1111111);
				for(UINT m = 0; m < 7; m++)
				{
					if((dayFlag % 10) == 1)
					{
						data.dayFlag[m] = true;
					}else
					{
						data.dayFlag[m] = false;
					}
					dayFlag /= 10;
				}
				data.startHour = CParser::GetValueInt(sLine, "start_hour", 0);
				data.startMinute = CParser::GetValueInt(sLine, "start_minute", 0);
				data.endHour = CParser::GetValueInt(sLine, "end_hour", INT_MAX);

				data.respawnTime = CParser::GetValueInt(sLine, "respawn_time", 0);
				data.saveInDB = CParser::GetValueInt(sLine, "save_in_db");
				
				string sPos = CParser::GetValueString(sLine, "position");
				//pos={148560;27104;-2208;16356}
				sPos = CParser::Replace(sPos, '{', ' ');
				sPos = CParser::Replace(sPos, '}', ' ');
				sPos = CParser::Replace(sPos, ';', ' ');
				stringstream sstrpos;
				sstrpos << sPos;
				sstrpos >> data.x >> data.y >> data.z >> data.heading;

				{
					string sPos = CParser::GetValueString(sLine, "position2");
					//pos={148560;27104;-2208;16356}
					sPos = CParser::Replace(sPos, '{', ' ');
					sPos = CParser::Replace(sPos, '}', ' ');
					sPos = CParser::Replace(sPos, ';', ' ');
					stringstream sstrpos;
					sstrpos << sPos;
					sstrpos >> data.x2 >> data.y2 >> data.z2 >> data.heading2;
				}

				{
					string sPos = CParser::GetValueString(sLine, "position3");
					//pos={148560;27104;-2208;16356}
					sPos = CParser::Replace(sPos, '{', ' ');
					sPos = CParser::Replace(sPos, '}', ' ');
					sPos = CParser::Replace(sPos, ';', ' ');
					stringstream sstrpos;
					sstrpos << sPos;
					sstrpos >> data.x3 >> data.y3 >> data.z3 >> data.heading3;
				}

							
				
				string sAiParams = CParser::GetValueString(sLine, "ai_parameters");
				//ai_parameters={[fnAgitMap]=[gludin];[fnAgitMap]=[gludin];[fnAgitMap]=[gludin]}
				sAiParams = CParser::Replace(sAiParams, '{', ' ');
				sAiParams = CParser::Replace(sAiParams, '}', ' ');
				sAiParams = CParser::Trim(sAiParams);
				sAiParams = CParser::Replace(sAiParams, ';', ' ');
				stringstream sstr;
				sstr << sAiParams;
				string sParam;
				while(sstr >> sParam)
				{
					//[fnAgitMap]=[gludin]
					sParam = CParser::Replace(sParam, '=', ' ');
					sParam = CParser::Replace(sParam, ']', ' ');
					sParam = CParser::Replace(sParam, '[', ' ');
					
					stringstream sstr2;
					sstr2 << sParam;
					string p1, p2;
					sstr2 >> p1 >> p2;
					wstring wParam1 = StringToWString(p1);
					wstring wParam2 = StringToWString(p2);
					if(wParam2.find(L"@") == 0)
					{
						wParam2 = wParam2.substr(1, (wParam2.size() - 1 ));
						int skillId, skillLevel;
						g_SkillDB.GetSkillIdLevelByName((PWCHAR)wParam2.c_str(), &skillId, &skillLevel);
						if(skillId > 0)
						{
							DWORD classId = (skillId << 8) + skillLevel;
							wstringstream wsstr2;
							wsstr2 << classId;
							wsstr2 >> wParam2;							
						}else
						{
							g_Log.Add(CLog::Error, "[%s] Invalid skill name[%S]!", __FUNCTION__, wParam2.c_str());
						}
					}
					data.ai_parameters.insert(pair<wstring, wstring>(wParam1, wParam2));
				}

				lData.push_back(data);
			}
			else if(sLine.find("npc_event_begin") == 0) //EVENT DATA
			{
				//npc_event_begin	event_id=1	npc_event_name=100100	start_date=2010-10-29-20-00	end_date=2010-10-29-20-00	npc_event_end;
				//npc_event_begin	event_id=2	npc_event_name=medal	day_flag=111	start_hour=10	start_minute=10	end_hour=10	npc_event_end;
				CNpcSpawnEventDefine data;
				data.eventID = CParser::GetValueInt(sLine, "event_id", 0);
				data.eventName = CParser::GetValueString(sLine, "npc_event_name");
				string sStart = CParser::GetValueString(sLine, "start_date");
				if(sStart.size() > 1)
				{
					int year, month, day, hour, minute;
					sscanf(sStart.c_str(), "%d-%d-%d-%d-%d", &year, &month, &day, &hour, &minute);

					data.startDate = ConvertTime(year, month, day, hour, minute);
				}else
					data.startDate = 0;

				string sEnd = CParser::GetValueString(sLine, "end_date");
				if(sEnd.size() > 1)
				{
					int year, month, day, hour, minute;
					sscanf(sEnd.c_str(), "%d-%d-%d-%d-%d", &year, &month, &day, &hour, &minute);
					
					data.endDate = ConvertTime(year, month, day, hour, minute);
				}else
					data.endDate = INT_MAX;
			
				UINT dayFlag = CParser::GetValueInt(sLine, "day_flag", 1111111);
				for(UINT m = 0; m < 7; m++)
				{
					if((dayFlag % 10) == 1)
					{
						data.dayFlag[m] = true;
					}else
					{
						data.dayFlag[m] = false;
					}
					dayFlag /= 10;
				}
				data.startHour = CParser::GetValueInt(sLine, "start_hour", 0);
				data.startMinute = CParser::GetValueInt(sLine, "start_minute", 0);
				data.endHour = CParser::GetValueInt(sLine, "end_hour", INT_MAX);

				/*wstring announce1 = Parser::ParseOptionString(line, L"announce_spawn");
				announce1 = Parser::Replace(announce1, L'{', L' ');
				announce1 = Parser::Replace(announce1, L'}', L' ');
				announce1 = Parser::Replace(announce1, L'_', L' ');
				wstring announce2 = Parser::ParseOptionString(line, L"announce_despawn");
				announce2 = Parser::Replace(announce2, L'{', L' ');
				announce2 = Parser::Replace(announce2, L'}', L' ');
				announce2 = Parser::Replace(announce2, L'_', L' ');

				data.AnnounceSpawn = announce1;
				data.AnnounceDeSpawn = announce2;*/
				lData2.push_back(data);
			}
		}
		file.close();
	}

	Unlock();
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] npcs.", __FUNCTION__, lData.size());
	g_Log.Add(CLog::Blue, "[%s] Loaded [%d] events.", __FUNCTION__, lData2.size());
}

time_t CNpcMaker::GetFixedSpawnTime(tmEx startTime, time_t spawnTime, DWORD spawnReuse)
{
	time_t currentTime = time(NULL);
	time_t fixedSpawnTime = 0;
	if(startTime.tm_year > 0)
	{
		time_t start = mktime(&startTime);
		if(start < spawnTime)
		{
			time_t diffTime = spawnTime - start;
			diffTime /= spawnReuse;
			fixedSpawnTime = start + (diffTime*spawnReuse);
		}
	}else
	{
		fixedSpawnTime = spawnTime;
	}

	return fixedSpawnTime;
}

void CNpcMaker::SpawnTick(CNpcSpawnDefine& spawnDefine)
{
	if(spawnDefine.npcClassId)
	{
		time_t currentTime = time(0);
		tm timeInfo;
		GetTimeInfo(timeInfo);
		if(currentTime >= spawnDefine.startDate && currentTime < spawnDefine.endDate)
		{
			//check for day flag
			if(spawnDefine.dayFlag[timeInfo.tm_wday])
			{
				if(spawnDefine.respawnTime == 0)
				{
					if(spawnDefine.startHour == timeInfo.tm_hour && spawnDefine.startMinute == timeInfo.tm_min)
					{
						if(spawnDefine.spawnTime + 90 < currentTime)
						{
							SpawnNpc(spawnDefine);
						}
					}
				}else if(spawnDefine.startHour <= timeInfo.tm_hour && spawnDefine.endHour > timeInfo.tm_hour)
				{
					//check for minute
					if(spawnDefine.startMinute <= timeInfo.tm_min || spawnDefine.startHour < timeInfo.tm_hour)
					{
						//check for respawn time
						if( (spawnDefine.deathTime + spawnDefine.respawnTime) < currentTime )
						{
							SpawnNpc(spawnDefine);
						}
					}
				}
			}
		}
	}
}

void CNpcMaker::DespawnTick(CNpcSpawnDefine& spawnDefine)
{
	
	if(spawnDefine.npcObjectId)
	{
		time_t currentTime = time(0);
		tm timeInfo;
		GetTimeInfo(timeInfo);
		if(currentTime >= spawnDefine.startDate && currentTime < spawnDefine.endDate)
		{
			//check end hour
			if(spawnDefine.endHour <= timeInfo.tm_hour)
			{
				DespawnNpc(spawnDefine);
			}else if(spawnDefine.endHour == 24 && timeInfo.tm_hour == 23 && timeInfo.tm_min == 59 && timeInfo.tm_sec > 50)
			{
				DespawnNpc(spawnDefine);
			}
		}else
		{
			DespawnNpc(spawnDefine);
		}
	}
}

void CNpcMaker::TimerExpired()
{
	guard;

	if(requestReload)
	{
		Initialize();
		requestReload = false;
	}

	if(m_enabled)
	{
		Lock();
		
		if(NpcServer::IsConnected())
		{
			if(loadedFromDB)
			{
				time_t currentTime = time(NULL);
				for(SpawnDefineList::iterator Iter = lData.begin();Iter!=lData.end();Iter++)
				{
					if(Iter->npcObjectId)
					{
						DespawnTick(*Iter);
					}else
					{
						SpawnTick(*Iter);
					}
				}
			}else
			{
				if(!requestedDB)
				{
					g_DB.RequestLoadNpcDeath();
					requestedDB = true;
				}
			}
			//New EventData
			for(SpawnEventDefineList::iterator Iter = lData2.begin();Iter!=lData2.end();Iter++)
			{
				if(Iter->spawned)
				{
					DespawnEventTick(*Iter);
				}else
				{
					SpawnEventTick(*Iter);
				}
			}
		}
		Unlock();
	}
	unguard;
}

bool CNpcMaker::BlockTeleportNpcPosEx(wstring wName)
{
	if(teleportEpicPer != 1.0)
	{
//		g_Log.Add(CLog::Error, "[%s] 11111111", __FUNCTION__);
		if(wName == L"baium_1" || wName == L"baium_2" || wName == L"baium_3" || wName == L"baium_4")
		{
			for(SpawnDefineList::iterator Iter = lData.begin();Iter!=lData.end();Iter++)
			{
				if(Iter->npcObjectId)
				{
					if(Iter->npcClassId == 1029020)
					{
						CNPC* pNPC = CNPC::GetNPCByServerId(&Iter->npcObjectId);
						if(pNPC->ValidCreature())
						{
							if((pNPC->pSD->MaxHP *= teleportEpicPer) < pNPC->pSD->fHP)
							{
								return true;
							}
						}
					}
				}
			}
		}

		if(wName == L"antaras_1" || wName == L"antaras_2" || wName == L"antaras_3" || wName == L"antaras_4")
		{

//			g_Log.Add(CLog::Error, "[%s] 2222222222", __FUNCTION__);
			for(SpawnDefineList::iterator Iter = lData.begin();Iter!=lData.end();Iter++)
			{
				if(Iter->npcObjectId)
				{
//					g_Log.Add(CLog::Error, "[%s] 333333 [%d]", __FUNCTION__, Iter->npcObjectId);
					if(Iter->npcClassId == 1029019)
					{
//						g_Log.Add(CLog::Error, "[%s] 44444444 [%d]", __FUNCTION__, Iter->npcClassId);
						CNPC* pNPC = CNPC::GetNPCByServerId(&Iter->npcObjectId);
						if(pNPC->ValidCreature())
						{
//							g_Log.Add(CLog::Error, "[%s] 55555555 [%f][%f][%f]", __FUNCTION__, pNPC->pSD->MaxHP *= teleportEpicPer, pNPC->pSD->fHP, teleportEpicPer);
							if(pNPC->pSD->fHP < (pNPC->pSD->MaxHP *= teleportEpicPer))
							{
//								g_Log.Add(CLog::Error, "[%s] 6666666666", __FUNCTION__);
								return true;
							}
						}
					}
				}
			}
		}

		if(wName == L"valakas_1" || wName == L"valakas_2" || wName == L"valakas_3" || wName == L"valakas_4")
		{
			for(SpawnDefineList::iterator Iter = lData.begin();Iter!=lData.end();Iter++)
			{
				if(Iter->npcObjectId)
				{
					if(Iter->npcClassId == 1029028)
					{
						CNPC* pNPC = CNPC::GetNPCByServerId(&Iter->npcObjectId);
						if(pNPC->ValidCreature())
						{
							if((pNPC->pSD->MaxHP *= teleportEpicPer) < pNPC->pSD->fHP)
							{
								return true;
							}
						}
					}
				}
			}
		}

		if(wName == L"queen_ant_1" || wName == L"queen_ant_2" || wName == L"queen_ant_3" || wName == L"queen_ant_4")
		{
			for(SpawnDefineList::iterator Iter = lData.begin();Iter!=lData.end();Iter++)
			{
				if(Iter->npcObjectId)
				{
					if(Iter->npcClassId == 1029001)
					{
						CNPC* pNPC = CNPC::GetNPCByServerId(&Iter->npcObjectId);
						if(pNPC->ValidCreature())
						{
							if((pNPC->pSD->MaxHP *= teleportEpicPer) < pNPC->pSD->fHP)
							{
								return true;
							}
						}
					}
				}
			}
		}

		if(wName == L"orfen_1" || wName == L"orfen_2" || wName == L"orfen_3" || wName == L"orfen_4")
		{
			for(SpawnDefineList::iterator Iter = lData.begin();Iter!=lData.end();Iter++)
			{
				if(Iter->npcObjectId)
				{
					if(Iter->npcClassId == 1029014)
					{
						CNPC* pNPC = CNPC::GetNPCByServerId(&Iter->npcObjectId);
						if(pNPC->ValidCreature())
						{
							if((pNPC->pSD->MaxHP *= teleportEpicPer) < pNPC->pSD->fHP)
							{
								return true;
							}
						}
					}
				}
			}
		}

		if(wName == L"zaken_1" || wName == L"zaken_2" || wName == L"zaken_3" || wName == L"zaken_4")
		{
			for(SpawnDefineList::iterator Iter = lData.begin();Iter!=lData.end();Iter++)
			{
				if(Iter->npcObjectId)
				{
					if(Iter->npcClassId == 1029022)
					{
						CNPC* pNPC = CNPC::GetNPCByServerId(&Iter->npcObjectId);
						if(pNPC->ValidCreature())
						{
							if((pNPC->pSD->MaxHP *= teleportEpicPer) < pNPC->pSD->fHP)
							{
								return true;
							}
						}
					}
				}
			}
		}

		if(wName == L"core_1" || wName == L"core_2" || wName == L"core_3" || wName == L"core_4")
		{
			for(SpawnDefineList::iterator Iter = lData.begin();Iter!=lData.end();Iter++)
			{
				if(Iter->npcObjectId)
				{
					if(Iter->npcClassId == 1029006)
					{
						CNPC* pNPC = CNPC::GetNPCByServerId(&Iter->npcObjectId);
						if(pNPC->ValidCreature())
						{
							if((pNPC->pSD->MaxHP *= teleportEpicPer) < pNPC->pSD->fHP)
							{
								return true;
							}
						}
					}
				}
			}
		}
	}
	return false;
}

void CNpcMaker::SetRequestReload()
{
	Lock();
	requestReload = true;
	Unlock();
}

void CNpcMaker::SpawnNpc(CNpcSpawnDefine &data)
{
	int nClassID = data.npcClassId;
	const WCHAR* wszName = g_ObjectDB.GetName(nClassID);

	//1025325 = barakiel
	//1029014 = orfen

	if(nClassID == 1025325 || nClassID == 1029014)
	{
		const WCHAR* wszName = g_ObjectDB.GetName(nClassID);
		CNPC *pNPC = g_ObjectDB.CreateNPC(nClassID);
		if(pNPC)
		{
			const WCHAR* wszAI = g_ObjectDB.GetAI(nClassID);
			if(wszAI)
			{ 
				//ai params
				CHAR ai_params[4096];
				int ai_params_len = 0;
				int nAiParams = 0;
				memset(ai_params, 0, sizeof(ai_params));
				for(map<const wstring, const wstring>::iterator it = pNPC->pND->aiParams.begin(); it != pNPC->pND->aiParams.end(); it++)
				{
					ai_params_len += Assemble(&ai_params[ai_params_len], 4096 - ai_params_len, "SS", it->first.c_str(), it->second.c_str());
					nAiParams++;
				}

				//Fill data with correct info
				CHAR buff[8190];
				memset(buff, 0, 8190);
				int nBuffSize = Assemble(buff, 8190,"cddpddddddddSdb", 0x01, pNPC->pSD->nServerIndex, pNPC->nObjectID, 
					0, 0, data.x, data.y, data.z, data.heading, 0, 0, 0, wszAI, nAiParams, ai_params_len, ai_params);
				NpcServer::Send(nBuffSize, buff);
				data.npcObjectId = pNPC->nObjectID;
				data.spawnTime = time(NULL);
			}else
				g_Log.Add(CLog::Error, "[%s] There is no AI specified for npc with class id[%d]", __FUNCTION__, nClassID);
		}else
			g_Log.Add(CLog::Error, "[%s] There is no npc with class id[%d]", __FUNCTION__, nClassID);



	}
	else
	{
		CNPC *pNPC = g_ObjectDB.CreateNPC(nClassID);
		if(pNPC)
		{
			const WCHAR* wszAI = g_ObjectDB.GetAI(nClassID);
			if(wszAI)
			{
				//ai params
				CHAR ai_params[4096];
				int ai_params_len = 0;
				int nAiParams = 0;
				memset(ai_params, 0, sizeof(ai_params));
				for(map<wstring, wstring>::iterator Iter = data.ai_parameters.begin();Iter!=data.ai_parameters.end();Iter++)
				{
					ai_params_len += Assemble(&ai_params[ai_params_len], 4096 - ai_params_len, "SS", Iter->first.c_str(), Iter->second.c_str());
				//	g_Log.Add(CLog::Blue, "[%s] Npc[%S] param[%S] value[%S]", __FUNCTION__, wszName, Iter->first.c_str(), Iter->second.c_str());
					nAiParams++;
				}

				//Fill data with correct info
				CHAR buff[8190];
				memset(buff, 0, 8190);


				int locX = data.x;
				int locY = data.y;
				int locZ =  data.z;
				int heading = data.heading;

				if(data.x2 > 0 && data.x3 > 0)
				{
					int randon = g_Random.RandInt(3);

					if(randon == 0)
					{
						locX = data.x;
						locY = data.y;
						locZ =  data.z;
						heading = data.heading;				
					}
					else if(randon == 1)
					{
						locX = data.x2;
						locY = data.y2;
						locZ =  data.z2;
						heading = data.heading2;		
					}
					else if(randon == 2)
					{
						locX = data.x3;
						locY = data.y3;
						locZ =  data.z3;
						heading = data.heading3;		
					}
				}

				teleportPos.x = locX;
				teleportPos.y = locY;
				teleportPos.z = locZ;


				int nBuffSize = Assemble(buff, 8190,"cddpddddddddSdb", 0x01, pNPC->pSD->nServerIndex, pNPC->nObjectID, 
					0, 0, locX, locY, locZ,
					heading, 0, 0, 0, wszAI, nAiParams, ai_params_len, ai_params);
				NpcServer::Send(nBuffSize, buff);
				data.npcObjectId = pNPC->nObjectID;
				data.spawnTime = time(NULL);
			}else
				g_Log.Add(CLog::Error, "[%s] There is no AI specified for npc with class id[%d]", __FUNCTION__, nClassID);
		}else
			g_Log.Add(CLog::Error, "[%s] There is no npc with class id[%d]", __FUNCTION__, nClassID);

	}

}

void CNpcMaker::DespawnNpc(CNpcSpawnDefine& spawnDefine)
{
	CNPC* pNPC = CNPC::GetNPCByServerId(&spawnDefine.npcObjectId);
	if(pNPC->ValidCreature())
	{
		pNPC->KillNPC();
	}
}

void CNpcMaker::ByPassTeleport(User* pUser)
{
	if(teleportPos.x > 0)
		PlayerAction::OnTeleportToLocation(pUser, teleportPos.x, teleportPos.y, teleportPos.z, false);
}

void CNpcMaker::LoadedFromDB(int npcClassId, DWORD spawnTime)
{
	Lock();
	for(SpawnDefineList::iterator Iter = lData.begin();Iter!=lData.end();Iter++)
	{
		if(Iter->npcClassId == npcClassId)
		{
		//	Iter->spawnTime = GetFixedSpawnTime(Iter->startDate, spawnTime, Iter->respawnTime);
			break;
		}
	}
	Unlock();
}

void CNpcMaker::SetLoadedFromDB(bool Value)
{ 
	Lock();
	loadedFromDB = Value; 
	Unlock(); 
};

void CNpcMaker::OnNpcDie(CNPC *pNPC, bool locked)
{
	if(m_enabled)
	{
		if(pNPC->ValidCreature())
		{
			if(!locked)
			{
				Lock();
			}
			for(SpawnDefineList::iterator Iter = lData.begin();Iter!=lData.end();Iter++)
			{
				if(Iter->npcObjectId == pNPC->nObjectID)
				{
					Iter->npcObjectId = 0;
					Iter->deathTime = time(NULL);

					if(Iter->saveInDB)
					{
						g_DB.RequestSaveNpcDeath(Iter->npcClassId, Iter->deathTime);	//should be spawn time depends on how should it work
					}
					break;
				}
			}
			if(!locked)
			{
				Unlock();
			}
		}
	}
}

void CNpcMaker::DespawnAll()
{
	for(SpawnDefineList::iterator Iter = lData.begin();Iter!=lData.end();Iter++)
	{
		if(Iter->npcObjectId)
		{
			//despawn
			CNPC* pNPC = CNPC::GetNPCByServerId(&Iter->npcObjectId);
			if(pNPC->ValidCreature())
			{
				pNPC->KillNPC();
			}
		}
	}
	lData.clear();
	for(SpawnEventDefineList::iterator Iter = lData2.begin();Iter!=lData2.end();Iter++)
	{
		wstring EventName(Iter->eventName.begin(), Iter->eventName.end());
		DisableNpcPosEvent(EventName.c_str());
	}
	lData2.clear();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void CNpcMaker::SpawnEventTick(CNpcSpawnEventDefine& spawnDefine)
{
	if(spawnDefine.eventID)
	{
		time_t currentTime = time(0);
		tm timeInfo;
		GetTimeInfo(timeInfo);
		if(currentTime >= spawnDefine.startDate && currentTime < spawnDefine.endDate)
		{
			//check for day flag
			if(spawnDefine.dayFlag[timeInfo.tm_wday])
			{
				if(spawnDefine.startHour == timeInfo.tm_hour && spawnDefine.startMinute == timeInfo.tm_min)
				{
					spawnDefine.spawned = true;
					//Make the Announce
					//Utils::BroadcastToAllUser_Announce(spawnDefine.AnnounceSpawn.c_str());
					wstring EventName(spawnDefine.eventName.begin(), spawnDefine.eventName.end());
					EnableNpcPosEvent(EventName.c_str());
				}
			}
		}
	}
}

void CNpcMaker::DespawnEventTick(CNpcSpawnEventDefine& spawnDefine)
{
	if(spawnDefine.spawned)
	{
		time_t currentTime = time(0);
		tm timeInfo;
		GetTimeInfo(timeInfo);
		if(currentTime >= spawnDefine.startDate && currentTime < spawnDefine.endDate)
		{
			//check end hour
			if(spawnDefine.endHour <= timeInfo.tm_hour)
			{
				spawnDefine.spawned = false;
				//Make the Announce
				//Utils::BroadcastToAllUser_Announce(spawnDefine.AnnounceDespawn.c_str());
				wstring EventName(spawnDefine.eventName.begin(), spawnDefine.eventName.end());
				DisableNpcPosEvent(EventName.c_str());
			}
			else if(spawnDefine.endHour == 24 && timeInfo.tm_hour == 23 && timeInfo.tm_min == 59 && timeInfo.tm_sec > 50)
			{
				spawnDefine.spawned = false;
				//Make the Announce
				//Utils::BroadcastToAllUser_Announce(spawnDefine.AnnounceDespawn.c_str());
				wstring EventName(spawnDefine.eventName.begin(), spawnDefine.eventName.end());
				DisableNpcPosEvent(EventName.c_str());
			}
		}
		else
		{
			spawnDefine.spawned = false;
			//Make the Announce
			//Utils::BroadcastToAllUser_Announce(spawnDefine.AnnounceDespawn.c_str());
			wstring EventName(spawnDefine.eventName.begin(), spawnDefine.eventName.end());
			DisableNpcPosEvent(EventName.c_str());
		}
	}
}