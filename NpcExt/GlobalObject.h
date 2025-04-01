#pragma once

class CGlobalObject
{
public:
	static void TeleportMPCC(LPVOID lpGlobalObject, PUINT64 lpParams);
	static void TeleportMPCCByIndex(LPVOID lpGlobalObject, PUINT64 lpParams);
	static void SetPCLevel(LPVOID lpGlobalObject, PUINT64 lpParams);
	static void FlagUser(LPVOID lpGlobalObject, PUINT64 lpParams);
	static void TvTEvent(LPVOID lpGlobalObject, PUINT64 lpParams);
	static void BlueFlagEvent(LPVOID lpGlobalObject, PUINT64 lpParams);
	static void RedFlagEvent(LPVOID lpGlobalObject, PUINT64 lpParams);
	static void AddPCSocial(LPVOID lpGlobalObject, PUINT64 lpParams);
	static void UpdatePledgeNameValue(LPVOID lpGlobalObject, PUINT64 lpParams);
	static void StopEvent(LPVOID lpGlobalObject, PUINT64 lpParams);
	static void CastBuffForQuestReward(LPVOID lpGlobalObject, PUINT64 lpParams);
};