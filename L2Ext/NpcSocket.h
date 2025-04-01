#pragma once

#include "NpcOpCode.h"

class CNpcSocket
{
public:
	static void Initialize();
	static bool Reply(CNpcSocket* pSocket, const unsigned char* packet);
	bool NpcDummy(const unsigned char* packet);
	bool TestPacket(const unsigned char* packet);
	bool InitializeEra(const unsigned char* packet);
	bool ProcessingEraNpcDone(const unsigned char* packet);
	bool ChangeEra(const unsigned char* packet);
	bool TeleportMPCC(const unsigned char* packet);
	bool TeleportMPCCByIndex(const unsigned char* packet);
	bool SetPCLevel(const unsigned char* packet);
	bool AddPCSocial(const unsigned char* packet);
	bool UpdatePledgeNameValue(const unsigned char* packet);
	bool CastBuffForQuestReward(const unsigned char* packet);
	bool FlagPlayer(const unsigned char* packet);
	bool TvTEvent(const unsigned char* packet);
	bool BlueFlagEvent(const unsigned char *packet);
	bool RedFlagEvent(const unsigned char *packet);
	bool StopEvent(const unsigned char *packet);
	bool AnnounceAnticipado(const unsigned char *packet);


	
	static bool NpcChangeSubJob(CNpcSocket *pSocket, const unsigned char* packet);
	static bool NpcCreateSubJob(CNpcSocket *pSocket, const unsigned char* packet);
	static bool NpcCreateSubJob2(CNpcSocket *pSocket, const unsigned char* packet);
	static bool NpcInstantTeleportInMyTerritory(CNpcSocket *pSocket, const unsigned char* packet);
};