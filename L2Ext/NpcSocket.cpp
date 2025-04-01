#include "StdAfx.h"
#include "MPCC.h"
#include "TerritoryEx.h"
#include "UserCache.h"
#include "TvT.h"

/*
 Begin handler table BF4100
 //0x38 opCode = Dummy packet
 End handler table BF44E0
*/

extern BOOL g_NoPermitirDosTanques;

extern BOOL g_LimitedSubClass;
extern INT32 g_TopeSubClassRace_Human;
extern INT32 g_TopeSubClassRace_Elf;
extern INT32 g_TopeSubClassRace_DarkElf;
extern INT32 g_TopeSubClassRace_Orc;
extern INT32 g_TopeSubClassRace_Dwarf;

extern BOOL g_LimitedSubClassRace;

std::vector<std::pair<std::wstring, int> > AnnounceRaidBossAnticipado;
BOOL AnnounceRaidBossAnticipadoActualizar = false;

void CNpcSocket::Initialize()
{
	g_HookManager.WriteMemoryDWORD(0xBF4410, (DWORD)NpcCreateSubJob);
	g_HookManager.WriteMemoryDWORD(0xBF4418, (DWORD)NpcChangeSubJob);
	g_HookManager.WriteMemoryDWORD(0xBF4420, (DWORD)NpcCreateSubJob2);
	g_HookManager.WriteMemoryDWORD(0xBF4210, (DWORD)NpcInstantTeleportInMyTerritory);
	g_HookManager.WriteMemoryDWORD(0xBF42C0, (DWORD)Reply);
}

bool CNpcSocket::Reply(CNpcSocket *pSocket, const unsigned char* packet)
{
	DWORD OpCode = 0;
	packet = (PUCHAR)Disassemble(packet, "d", &OpCode);
	
//	g_Log.Add(CLog::Blue, "[%s] OpCode[%d]", __FUNCTION__, OpCode);

	switch(OpCode)
	{
	case TEST_NPC_OPCODE:
		{
			return pSocket->TestPacket(packet);
			break;
		}
	case INITIALIZE_ERA:
		{
			if(g_Config.IsSet(CConfig::ERA_SYSTEM))
				return pSocket->InitializeEra(packet);
			break;
		}
	case PROCESSING_ERA_NPC_DONE:
		{
			if(g_Config.IsSet(CConfig::ERA_SYSTEM))
				return pSocket->ProcessingEraNpcDone(packet);
			break;
		}
	case CHANGE_ERA:
		{
			if(g_Config.IsSet(CConfig::ERA_SYSTEM))
				return pSocket->ChangeEra(packet);
			break;
		}
	case TELEPORT_MPCC:
		{
			return pSocket->TeleportMPCC(packet);
			break;
		}
	case TELEPORT_MPCC_BY_INDEX:
		{
			return pSocket->TeleportMPCCByIndex(packet);
			break;
		}
	case SET_PC_LEVEL:
		{
			return pSocket->SetPCLevel(packet);
			break;
		}
	case ADD_PC_SOCIAL:
		{
			return pSocket->AddPCSocial(packet);
			break;
		}
	case UPDATE_PLEDGE_NAME_VALUE:
		{
			return pSocket->UpdatePledgeNameValue(packet);
			break;
		}
	case FLAG_PLAYER:
		{
			return pSocket->FlagPlayer(packet);
			break;
		}
	case TVT_EVENT:
		{
			return pSocket->TvTEvent(packet);
			break;
		}
	case BLUE_FLAG_EVENT:
		{
			return pSocket->BlueFlagEvent(packet);
			break;
		}
	case RED_FLAG_EVENT:
		{
			return pSocket->RedFlagEvent(packet);
			break;
		}
	case STOP_EVENT:
		{
			return pSocket->StopEvent(packet);
			break;
		}
	case CAST_BUFF_FOR_QUEST_REWARD_VALUE:
		{
			return pSocket->CastBuffForQuestReward(packet);
			break;
		}
	case ANNOUNCE_ANTICIPADO:
		{
			return pSocket->AnnounceAnticipado(packet);
			break;
		}
	default:
		return pSocket->NpcDummy(packet);
		break;
	}

	return false;
};

bool CNpcSocket::BlueFlagEvent(const unsigned char *packet)
{
	guard;
	UINT talkerId = 0;
	Disassemble(packet, "d", &talkerId);
	if(talkerId > 0)
	{
		if(User *pUser = User::GetUserBySID(&talkerId))
		{
			if(pUser->ValidUser())
			{
				g_TvT.NPCActionBlueFlag(pUser);
			}
		}
		else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find talker[%d]!", __FUNCTION__, talkerId);
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] null talker id!", __FUNCTION__);
	}

	unguard;
	return false;
}

bool CNpcSocket::RedFlagEvent(const unsigned char *packet)
{
	guard;
	UINT talkerId = 0;
	Disassemble(packet, "d", &talkerId);
	if(talkerId > 0)
	{
		if(User *pUser = User::GetUserBySID(&talkerId))
		{
			if(pUser->ValidUser())
			{
				g_TvT.NPCActionRedFlag(pUser);
			}
		}
		else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find talker[%d]!", __FUNCTION__, talkerId);
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] null talker id!", __FUNCTION__);
	}

	unguard;
	return false;
}

bool CNpcSocket::TvTEvent(const unsigned char *packet)
{
	guard;
	UINT talkerId = 0;
	Disassemble(packet, "d", &talkerId);
	if(talkerId > 0)
	{
		if(User *pUser = User::GetUserBySID(&talkerId))
		{
			if(pUser->ValidUser())
			{
				g_TvT.NPCAction(pUser);
			}
		}
		else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find talker[%d]!", __FUNCTION__, talkerId);
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] null talker id!", __FUNCTION__);
	}

	unguard;
	return false;
}

bool CNpcSocket::FlagPlayer(const unsigned char *packet)
{
	guard;
	UINT talkerId = 0;
	Disassemble(packet, "d", &talkerId);
	if(talkerId > 0)
	{
		if(User *pUser = User::GetUserBySID(&talkerId))
		{
			if(pUser->ValidUser())
			{
				pUser->SetPvPFlag();
				pUser->SetUserInfoChanged();
				pUser->SetCharInfoChanged();
			}
		}
		else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find talker[%d]!", __FUNCTION__, talkerId);
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] null talker id!", __FUNCTION__);
	}

	unguard;
	return false;
}

bool CNpcSocket::UpdatePledgeNameValue(const unsigned char* packet)
{
	guard;
	UINT talkerId = 0;
	INT32 value = 0;
	Disassemble(packet, "dd", &talkerId, &value);
	if(talkerId > 0)
	{
		if(User *pUser = User::GetUserBySID(&talkerId))
		{
			if(pUser->pSD->nPledgeID > 0)
			{
				if(CPledge *pPledge = pUser->GetPledge())
				{
					pPledge->UpdatePledgeNameValue(value);
					g_Logger.Add(L"[%s] Talker[%s] pledge[%s][%d] value[%d]", __FUNCTIONW__, pUser->pSD->wszName, pPledge->pSD->wszClanName, pPledge->pSD->nDBID, value);
				}
			}else
			{
				g_Log.Add(CLog::Error, "[%s] talker[%S] doesn't have a pledge - value[%d]", __FUNCTION__, pUser->pSD->wszName, value);
			}
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find talker[%d]!", __FUNCTION__, talkerId);
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] null talker id!", __FUNCTION__);
	}
	unguard;
	return false;
}



bool CNpcSocket::CastBuffForQuestReward(const unsigned char* packet)
{
	guard;
	UINT talkerId = 0;
	INT32 value = 0;
	Disassemble(packet, "dd", &talkerId, &value);
	if(talkerId > 0)
	{
		if(User *pUser = User::GetUserBySID(&talkerId))
		{
			SkillPchId skill = value;
			if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(skill.skillId, skill.level))
			{
				pSI->ActivateSkill(pUser, pUser);
			}

			//	g_Log.Add(CLog::Error, "[%s] BIEN[%d]!", __FUNCTION__, value);
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find talker[%d]!", __FUNCTION__, talkerId);
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] null talker id!", __FUNCTION__);
	}
	unguard;
	return false;
}



bool CNpcSocket::AnnounceAnticipado(const unsigned char* packet)
{
	guard;

	WCHAR name[25] = {0};
	memset(name, 0, sizeof(name));
	INT32 value = 0;
	Disassemble(packet, "Sd", sizeof(name), name, &value);

    // Convertir el valor a un tiempo en segundos desde el Epoch (1 de enero de 1970)
    time_t timestamp = static_cast<time_t>(value);

    // Convertir el tiempo a una estructura de tiempo local
    tm* localTime = localtime(&timestamp);

    // Obtener la hora y el minuto del tiempo local
    int hour = localTime->tm_hour;
    int minute = localTime->tm_min;

    // Crear una cadena de caracteres amplios para almacenar la hora y los minutos
    WCHAR tmp[32] = { 0 };

    // Formatear la hora y los minutos en una cadena de caracteres amplios
    swprintf(tmp, 32, L"%02d:%02d", hour, minute);

//	if (value >0)
//		g_Log.Add(CLog::Error, "[%s] npcName[%S] hora[%S] timestamp[%d] ", __FUNCTION__, name, tmp, value);

	bool comprobar = false;
	for (vector<pair<wstring, int>>::iterator Iter = AnnounceRaidBossAnticipado.begin(); Iter != AnnounceRaidBossAnticipado.end(); ++Iter) {
		if (Iter->first == name)
		{
			Iter->second = value;
			comprobar = true;
		}
	}

	if(!comprobar)
	{
		AnnounceRaidBossAnticipado.push_back(std::make_pair(name, value));

	}

	AnnounceRaidBossAnticipadoActualizar = true;


	unguard;
	return false;
}



bool CNpcSocket::AddPCSocial(const unsigned char *packet)
{
	guard;
	UINT talkerId = 0;
	UINT actionId = 0;
	Disassemble(packet, "dd", &talkerId, &actionId);
	if(talkerId > 0)
	{
		if(User *pUser = User::GetUserBySID(&talkerId))
		{
			if(actionId < 18)
			{
				pUser->SocialAction((SocialActionType)actionId);
			}else
			{
				g_Log.Add(CLog::Error, "[%s] Invalid social action[%d] talker[%S]", __FUNCTION__, actionId, pUser->pSD->wszName);
			}
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find talker[%d]!", __FUNCTION__, talkerId);
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] null talker id!", __FUNCTION__);
	}

	unguard;
	return false;
}

bool CNpcSocket::SetPCLevel(const unsigned char* packet)
{
	guard;
	UINT talkerId = 0;
	INT32 newLevel = 0;
	Disassemble(packet, "dd", &talkerId, &newLevel);

	if(talkerId > 0)
	{
		if(User *pUser = User::GetUserBySID(&talkerId))
		{
			if(newLevel > 0 && newLevel <= 80)
			{
				pUser->SetLevel(newLevel);
				g_Logger.Add(L"[%S] talker[%s] new level[%d]", __FUNCTION__, pUser->pSD->wszName, newLevel);
			}else
			{
				g_Log.Add(CLog::Error, "[%s] Invalid new level[%d] - talker[%S]!", __FUNCTION__, newLevel, pUser->pSD->wszName);
			}
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Cannot find talker[%d]!", __FUNCTION__, talkerId);
		}
	}else
	{
		g_Log.Add(CLog::Error, "[%s] null talker id!", __FUNCTION__);
	}
	unguard;
	return false;
}

bool CNpcSocket::TeleportMPCC(const unsigned char* packet)
{
	guard;

	UINT talkerId = 0;
	INT32 x = 0, y = 0, z = 0;
	Disassemble(packet, "dddd", &talkerId, &x, &y, &z);

	if(talkerId > 0)
	{
		User *pUser = User::GetUserBySID(&talkerId);
		if(pUser->ValidUser())
		{
			CMPCC::TeleportMPCC(pUser, x, y, z);
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Invalid user[%d]!", __FUNCTION__);
		}
	}
	unguard;
	return false;
}

bool CNpcSocket::TeleportMPCCByIndex(const unsigned char* packet)
{
	guard;

	UINT talkerId = 0;
	UINT index = 0;
	INT32 x = 0, y = 0, z = 0;
	Disassemble(packet, "ddddd", &talkerId, &index, &x, &y, &z);

	if(talkerId > 0)
	{
		User *pUser = User::GetUserBySID(&talkerId);
		if(pUser->ValidUser())
		{
			CMPCC::TeleportMPCCByIndex(pUser, index, x, y, z);
		}else
		{
			g_Log.Add(CLog::Error, "[%s] Invalid user[%d]!", __FUNCTION__);
		}
	}
	unguard;
	return false;
}

bool CNpcSocket::NpcDummy(const unsigned char* packet)
{
	typedef bool(*f)(CNpcSocket*, const unsigned char*);
	return f(0x6CF770)(this, packet);
}

bool CNpcSocket::InitializeEra(const unsigned char* packet)
{
	g_EraSystem.Initialize(packet);
	return false;
}

bool CNpcSocket::ProcessingEraNpcDone(const unsigned char* packet)
{
	WCHAR wEra[25]; memset(wEra, 0, sizeof(wEra));
	int nEraIndex = 0, nSpawned = 0;
	Disassemble(packet, "dSd", &nEraIndex, sizeof(wEra), wEra, &nSpawned);
	g_EraSystem.ProcessingFinished(nEraIndex, wEra, nSpawned);
	return false;
}

bool CNpcSocket::ChangeEra(const unsigned char* packet)
{
	WCHAR wEra[25]; memset(wEra, 0, sizeof(wEra));
	DWORD nEra = 0;
	DWORD nLastChanged = 0;
	Disassemble(packet, "dSd", &nEra, sizeof(wEra), wEra, &nLastChanged);
	g_EraSystem.ChangeEra(nEra, wEra, nLastChanged);
	return false;
}

bool CNpcSocket::TestPacket(const unsigned char* packet)
{
	int SubCode = 0;
	Disassemble(packet, "d", &SubCode);
	g_Log.Add(CLog::Blue, "[%s] SubCode[%d]", __FUNCTION__, SubCode);

	return false;
}

bool CNpcSocket::NpcCreateSubJob(CNpcSocket *pSocket, const unsigned char* packet)
{
	_NpcSockFunc NCSJ = (_NpcSockFunc) 0x006E30E0;
	int nNpcSID, nUserSID, nSubjobID;
	Disassemble(packet, "ddd", &nNpcSID, &nUserSID, &nSubjobID);
	CObjectSP UserSP;
	CObjectSP::FindObject(&UserSP, nUserSID);
	User *pUser = UserSP.pObject->GetUser();
	if(pUser->ValidUser())
	{
		//dark avenger				[dark_avenger] = 6				[hell_knight] = 91
		//shillien knight			[shillien_knight] = 33			[shillien_templar] = 106
		//Temple Knight				[temple_knight] = 20			[evas_templar] = 99
		//Paladin					[paladin] = 5					[phoenix_knight] = 90

		if (g_NoPermitirDosTanques)
		{
			if (nSubjobID == 6 || nSubjobID == 33 || nSubjobID == 20 || nSubjobID == 5)
			{
				if (pUser->pSD->nSubJobClass[0] == 6 || pUser->pSD->nSubJobClass[0] == 33 || pUser->pSD->nSubJobClass[0] == 20 || pUser->pSD->nSubJobClass[0] == 5 || pUser->pSD->nSubJobClass[0] == 91 || pUser->pSD->nSubJobClass[0] == 106 || pUser->pSD->nSubJobClass[0] == 99 || pUser->pSD->nSubJobClass[0] == 90)
				{
					pUser->SendSystemMessage(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
					return false;
				}
				if (pUser->pSD->nSubJobClass[1] == 6 || pUser->pSD->nSubJobClass[1] == 33 || pUser->pSD->nSubJobClass[1] == 20 || pUser->pSD->nSubJobClass[1] == 5 || pUser->pSD->nSubJobClass[1] == 91 || pUser->pSD->nSubJobClass[1] == 106 || pUser->pSD->nSubJobClass[1] == 99 || pUser->pSD->nSubJobClass[1] == 90)
				{
					pUser->SendSystemMessage(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
					return false;
				}
				if (pUser->pSD->nSubJobClass[2] == 6 || pUser->pSD->nSubJobClass[2] == 33 || pUser->pSD->nSubJobClass[2] == 20 || pUser->pSD->nSubJobClass[2] == 5 || pUser->pSD->nSubJobClass[2] == 91 || pUser->pSD->nSubJobClass[2] == 106 || pUser->pSD->nSubJobClass[2] == 99 || pUser->pSD->nSubJobClass[2] == 90)
				{
					pUser->SendSystemMessage(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
					return false;
				}
				if (pUser->pSD->nSubJobClass[3] == 6 || pUser->pSD->nSubJobClass[3] == 33 || pUser->pSD->nSubJobClass[3] == 20 || pUser->pSD->nSubJobClass[3] == 5 || pUser->pSD->nSubJobClass[3] == 91 || pUser->pSD->nSubJobClass[3] == 106 || pUser->pSD->nSubJobClass[3] == 99 || pUser->pSD->nSubJobClass[3] == 90)
				{
					pUser->SendSystemMessage(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
					return false;
				}
			}
		}

		if(g_LimitedSubClass)
		{
			int count = 0;

			for(UINT i=1;i<4;i++)
			{
				if (pUser->pSD->nSubJobClass[i] != -1)
					count++;
			}

			if ( pUser->pSD->nRace == 0 && count >= g_TopeSubClassRace_Human) //human
			{
				pUser->SendSystemMessage(L"No puedes realizar mas SubClasses.");
				return false;
			}
			else if ( pUser->pSD->nRace == 1 && count >= g_TopeSubClassRace_Elf)	//elf
			{
				pUser->SendSystemMessage(L"No puedes realizar mas SubClasses.");
				return false;
			}
			else if ( pUser->pSD->nRace == 2 && count >= g_TopeSubClassRace_DarkElf)	//dark elf
			{
				pUser->SendSystemMessage(L"No puedes realizar mas SubClasses.");
				return false;
			}
			else if ( pUser->pSD->nRace == 3 && count >= g_TopeSubClassRace_Orc)	//orc
			{
				pUser->SendSystemMessage(L"No puedes realizar mas SubClasses.");
				return false;
			}
			else if ( pUser->pSD->nRace == 4 && count >= g_TopeSubClassRace_Dwarf)	//dwarf
			{
				pUser->SendSystemMessage(L"No puedes realizar mas SubClasses.");
				return false;
			}
		}

		if(g_LimitedSubClassRace)
		{
			bool permitir = false;
			if ( pUser->pSD->nRace == 0 && (nSubjobID >= 0 && nSubjobID <= 9 || nSubjobID >= 88 && nSubjobID <= 93 || nSubjobID >= 10 && nSubjobID <= 17 || nSubjobID >= 94 && nSubjobID <= 98)) //human
				permitir=true;
			else if ( pUser->pSD->nRace == 1 && (nSubjobID >= 18 && nSubjobID <= 30 || nSubjobID >= 99 && nSubjobID <= 105))	//elf
				permitir=true;
			else if ( pUser->pSD->nRace == 2 && (nSubjobID >= 31 && nSubjobID <= 43 || nSubjobID >= 106 && nSubjobID <= 112))	//dark elf
				permitir=true;
			else if ( pUser->pSD->nRace == 3 && (nSubjobID >= 44 && nSubjobID <= 52 || nSubjobID >= 113 && nSubjobID <= 116))	//orc
				permitir=true;
			else if ( pUser->pSD->nRace == 4 && (nSubjobID >= 53 && nSubjobID <= 57 || nSubjobID >= 117 && nSubjobID <= 118))	//dwarf
				permitir=true;

			if (!permitir)
			{
				pUser->SendSystemMessage(L"No puedes mesclar subclasses con otra raza.");
					return false;
			}
		}


		DWORD nTime = time(NULL);
		if(pUser->pSD->nSubJobManipulateDelay > nTime)
		{
			pUser->SendSystemMessage(L"You have to wait 30 seconds between changing subclasses.");
			return false;
		}else
		{
			pUser->pSD->nSubJobManipulateDelay = nTime + 30;
		}
	}
	return NCSJ(pSocket, packet);
}
bool CNpcSocket::NpcChangeSubJob(CNpcSocket *pSocket, const unsigned char* packet)
{
	_NpcSockFunc NCSJ = (_NpcSockFunc) 0x006E3600;
	int nNpcSID, nUserSID, nSubjobID;
	Disassemble(packet, "ddd", &nNpcSID, &nUserSID, &nSubjobID);
	CObjectSP UserSP;
	CObjectSP::FindObject(&UserSP, nUserSID);
	User *pUser = UserSP.pObject->GetUser();
	if(pUser->ValidUser())
	{
		DWORD nTime = time(NULL);
		if(pUser->pSD->nSubJobManipulateDelay > nTime)
		{
			pUser->SendSystemMessage(L"You have to wait 30 seconds between changing subclasses.");
			return false;
		}else
		{
			pUser->pSD->nSubJobManipulateDelay = nTime + 30;
		}
	}
	return NCSJ(pSocket, packet);
}
bool CNpcSocket::NpcCreateSubJob2(CNpcSocket *pSocket, const unsigned char* packet)
{
	_NpcSockFunc NCSJ = (_NpcSockFunc) 0x006E3AF0;
	int nNpcSID, nUserSID, nSubjobID;
	Disassemble(packet, "ddd", &nNpcSID, &nUserSID, &nSubjobID);
	CObjectSP UserSP;
	CObjectSP::FindObject(&UserSP, nUserSID);
	User *pUser = UserSP.pObject->GetUser();
	if(pUser->ValidUser())
	{
		//dark avenger				[dark_avenger] = 6				[hell_knight] = 91
		//shillien knight			[shillien_knight] = 33			[shillien_templar] = 106
		//Temple Knight				[temple_knight] = 20			[evas_templar] = 99
		//Paladin					[paladin] = 5					[phoenix_knight] = 90

		if (g_NoPermitirDosTanques)
		{
			if (nSubjobID == 6 || nSubjobID == 33 || nSubjobID == 20 || nSubjobID == 5)
			{
				if (pUser->pSD->nSubJobClass[0] == 6 || pUser->pSD->nSubJobClass[0] == 33 || pUser->pSD->nSubJobClass[0] == 20 || pUser->pSD->nSubJobClass[0] == 5 || pUser->pSD->nSubJobClass[0] == 91 || pUser->pSD->nSubJobClass[0] == 106 || pUser->pSD->nSubJobClass[0] == 99 || pUser->pSD->nSubJobClass[0] == 90)
				{
					pUser->SendSystemMessage(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
					return false;
				}
				if (pUser->pSD->nSubJobClass[1] == 6 || pUser->pSD->nSubJobClass[1] == 33 || pUser->pSD->nSubJobClass[1] == 20 || pUser->pSD->nSubJobClass[1] == 5 || pUser->pSD->nSubJobClass[1] == 91 || pUser->pSD->nSubJobClass[1] == 106 || pUser->pSD->nSubJobClass[1] == 99 || pUser->pSD->nSubJobClass[1] == 90)
				{
					pUser->SendSystemMessage(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
					return false;
				}
				if (pUser->pSD->nSubJobClass[2] == 6 || pUser->pSD->nSubJobClass[2] == 33 || pUser->pSD->nSubJobClass[2] == 20 || pUser->pSD->nSubJobClass[2] == 5 || pUser->pSD->nSubJobClass[2] == 91 || pUser->pSD->nSubJobClass[2] == 106 || pUser->pSD->nSubJobClass[2] == 99 || pUser->pSD->nSubJobClass[2] == 90)
				{
					pUser->SendSystemMessage(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
					return false;
				}
				if (pUser->pSD->nSubJobClass[3] == 6 || pUser->pSD->nSubJobClass[3] == 33 || pUser->pSD->nSubJobClass[3] == 20 || pUser->pSD->nSubJobClass[3] == 5 || pUser->pSD->nSubJobClass[3] == 91 || pUser->pSD->nSubJobClass[3] == 106 || pUser->pSD->nSubJobClass[3] == 99 || pUser->pSD->nSubJobClass[3] == 90)
				{
					pUser->SendSystemMessage(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje.");
					return false;
				}
			}
		}

		if(g_LimitedSubClass)
		{
			int count = 0;

			for(UINT i=1;i<4;i++)
			{
				if (pUser->pSD->nSubJobClass[i] != -1)
					count++;
			}

			if ( pUser->pSD->nRace == 0 && count >= g_TopeSubClassRace_Human) //human
			{
				pUser->SendSystemMessage(L"No puedes realizar mas SubClasses.");
				return false;
			}
			else if ( pUser->pSD->nRace == 1 && count >= g_TopeSubClassRace_Elf)	//elf
			{
				pUser->SendSystemMessage(L"No puedes realizar mas SubClasses.");
				return false;
			}
			else if ( pUser->pSD->nRace == 2 && count >= g_TopeSubClassRace_DarkElf)	//dark elf
			{
				pUser->SendSystemMessage(L"No puedes realizar mas SubClasses.");
				return false;
			}
			else if ( pUser->pSD->nRace == 3 && count >= g_TopeSubClassRace_Orc)	//orc
			{
				pUser->SendSystemMessage(L"No puedes realizar mas SubClasses.");
				return false;
			}
			else if ( pUser->pSD->nRace == 4 && count >= g_TopeSubClassRace_Dwarf)	//dwarf
			{
				pUser->SendSystemMessage(L"No puedes realizar mas SubClasses.");
				return false;
			}
		}


		if(g_LimitedSubClassRace)
		{
			bool permitir = false;
			if ( pUser->pSD->nRace == 0 && (nSubjobID >= 0 && nSubjobID <= 9 || nSubjobID >= 88 && nSubjobID <= 93 || nSubjobID >= 10 && nSubjobID <= 17 || nSubjobID >= 94 && nSubjobID <= 98)) //human
				permitir=true;
			else if ( pUser->pSD->nRace == 1 && (nSubjobID >= 18 && nSubjobID <= 30 || nSubjobID >= 99 && nSubjobID <= 105))	//elf
				permitir=true;
			else if ( pUser->pSD->nRace == 2 && (nSubjobID >= 31 && nSubjobID <= 43 || nSubjobID >= 106 && nSubjobID <= 112))	//dark elf
				permitir=true;
			else if ( pUser->pSD->nRace == 3 && (nSubjobID >= 44 && nSubjobID <= 52 || nSubjobID >= 113 && nSubjobID <= 116))	//orc
				permitir=true;
			else if ( pUser->pSD->nRace == 4 && (nSubjobID >= 53 && nSubjobID <= 57 || nSubjobID >= 117 && nSubjobID <= 118))	//dwarf
				permitir=true;

			if (!permitir)
			{
				pUser->SendSystemMessage(L"No puedes mesclar subclasses con otra raza.");
					return false;
			}
		}


		DWORD nTime = time(NULL);
		if(pUser->pSD->nSubJobManipulateDelay > nTime)
		{
			pUser->SendSystemMessage(L"You have to wait 30 seconds between changing subclasses.");
			return false;
		}else
		{
			pUser->pSD->nSubJobManipulateDelay = nTime + 30;
		}
	}
	return NCSJ(pSocket, packet);
}

bool CNpcSocket::NpcInstantTeleportInMyTerritory(CNpcSocket *pSocket, const unsigned char* packet)
{
	guard;

	UINT temp;
	UINT npcId = 0;
	INT32 destX = 0, destY = 0, destZ = 0, range = 0;
	const unsigned char* pck = Disassemble(packet, "ddddddddddd", &npcId, &destX, &destY, &destZ, &range, &temp, &temp, &temp, &temp, &temp, &temp);

	UINT territoryCount = 0;
	pck = Disassemble(pck, "d", &territoryCount);
	vector<CTerritoryEx> bannedTerritories;
	//banned territory
	for(UINT territoryCounter = 0; territoryCounter < territoryCount; territoryCounter++)
	{
		UINT pointCount = 0;
		pck = Disassemble(pck, "d", &pointCount);
		CTerritoryEx territory;
		for(UINT pointCounter = 0;pointCounter < pointCount; pointCounter++)
		{
			INT32 x = 0, y = 0, z = 0;
			pck = Disassemble(pck, "ddd", &x, &y, &z);
			FVector pos;
			pos.x = static_cast<double>(x);
			pos.y = static_cast<double>(y);
			pos.z = static_cast<double>(z);
			territory.AddPoint(pos);
		//	g_Log.Add(CLog::Blue, "Point idx: %d loc: %d, %d, %d", pointCounter, x, y, z);
		}
		bannedTerritories.push_back(territory);
	}

	vector<CTerritoryEx> territories;
	//Territory data
	pck = Disassemble(pck, "d", &territoryCount);
	for(UINT territoryCounter = 0; territoryCounter < territoryCount; territoryCounter++)
	{
		UINT pointCount = 0;
		INT32 minZ = 0, maxZ = 0;
		pck = Disassemble(pck, "ddd", &pointCount, &maxZ, &minZ);
		CTerritoryEx territory;
		for(UINT pointCounter = 0;pointCounter < pointCount; pointCounter++)
		{
			INT32 x = 0, y = 0;
			pck = Disassemble(pck, "dd", &x, &y);
			FVector pos;
			pos.x = static_cast<double>(x);
			pos.y = static_cast<double>(y);
			pos.z = static_cast<double>((minZ + maxZ) / 2);
			territory.AddPoint(pos);

		//	g_Log.Add(CLog::Blue, "Point Z Range idx: %d loc: %d, %d MinZ: %d MaxZ: %d", pointCounter, x, y, minZ, maxZ);
		}
		territory.AddZRange(static_cast<double>(minZ), static_cast<double>(maxZ));
		territories.push_back(territory);
	}

	g_UserCache.InstantTeleportInMyTerritory(destX, destY, destZ, range, territories, bannedTerritories);

	bool ret = _NpcSockFunc(0x6EDAA0L)(pSocket, packet);
	unguard;
	return ret;
}

bool CNpcSocket::StopEvent(const unsigned char* packet)
{
	guard;

	INT32 eventid = 0;
	Disassemble(packet, "d", &eventid);


	if(eventid > 0)
	{
		if(eventid == 1)
			DisableNpcPosEvent(L"core_event");
		else if(eventid == 2)
			DisableNpcPosEvent(L"orfen_event");
		else if(eventid == 3)
			DisableNpcPosEvent(L"zaken_event");
		else if(eventid == 4)
			DisableNpcPosEvent(L"queen_ant_event");
		else if(eventid == 5)
			DisableNpcPosEvent(L"baium_event");
		else if(eventid == 6)
			DisableNpcPosEvent(L"antaras_event");
		else if(eventid == 7)
			DisableNpcPosEvent(L"valakas_event");
		else if(eventid == 8)
			DisableNpcPosEvent(L"frintessa_event");
	}
	else
	{
		g_Log.Add(CLog::Error, "[%s] Invalid eventid[%d]!", __FUNCTION__);
	}

	unguard;
	return false;
}